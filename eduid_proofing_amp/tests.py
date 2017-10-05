# -*- coding: utf-8 -*-

import bson
from datetime import datetime

from eduid_userdb.exceptions import UserDoesNotExist, UserHasUnknownData
from eduid_userdb.testing import MongoTestCase
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.personal_data import PersonalDataUser
from eduid_userdb.security import SecurityUser
from eduid_proofing_amp import attribute_fetcher, oidc_plugin_init, letter_plugin_init, lookup_mobile_plugin_init
from eduid_proofing_amp import email_plugin_init, phone_plugin_init, personal_data_plugin_init, security_plugin_init
from eduid_am.celery import celery, get_attribute_manager


class AttributeFetcherOldToNewUsersTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherOldToNewUsersTests, self).setUp(celery, get_attribute_manager)
        self.plugin_contexts = [
            oidc_plugin_init(celery.conf),
            letter_plugin_init(celery.conf),
            lookup_mobile_plugin_init(celery.conf)
        ]
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.userdb.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.userdb._drop_whole_collection()
        super(AttributeFetcherOldToNewUsersTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        now = datetime.now(tz=bson.tz_util.FixedOffset(0, 'UTC'))
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mail': 'john@example.com',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'added_timestamp': now
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'norEduPersonNIN': [u'123456781235'],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                    },
                    '$unset': {
                        'norEduPersonNIN': None
                    }
                }
            )

    def test_malicious_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mail': 'john@example.com',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336'
            }],
            'malicious': 'hacker',
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
        }

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.userdb._coll.insert(_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mail': 'john@example.com',
            'displayName': 'John',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336'
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'norEduPersonNIN': [u'123456781235'],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                    },
                    '$unset': {
                        'norEduPersonNIN': None
                    }
                }
            )

    def test_append_attributes_letter_proofing_data(self):
        self.maxDiff = None
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mail': 'john@example.com',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('1' * 24),
                'salt': '456',
            }],
            'norEduPersonNIN': [u'123456781235'],
            "letter_proofing_data": [
                {
                    "verification_code": u"secret code",
                    "verified": True,
                    "verified_by": u"eduid-idproofing-letter",
                    "created_ts": u'ts',
                    "official_address": {
                        u"OfficialAddress": {
                            u"PostalCode": u"12345",
                            u"City": u"LANDET",
                            u"Address2": u"ÖRGATAN 79 LGH 10"
                        },
                        u"Name": {
                            u"Surname": u"Testsson",
                            u"GivenName": u"Testaren Test",
                            u"GivenNameMarking": u"20"
                        }
                    },
                    u"number": u"123456781235",
                    u"created_by": u"eduid-idproofing-letter",
                    u"verified_ts": u'ts',
                    u"transaction_id": u"debug mode transaction id"
                }
            ],
        }
        proofing_user = ProofingUser(data=_data)
        letter_plugin_context = letter_plugin_init(celery.conf)
        letter_plugin_context.userdb.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
            '$set': {
                'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                "letter_proofing_data": [
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    }
                ]
            },
            '$unset': {
                'norEduPersonNIN': None
            }
        }
        self.assertDictEqual(
            actual_update,
            expected_update
        )

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)

        # Don't repeat the letter_proofing_data
        self.assertDictEqual(
            actual_update,
            expected_update
        )

        # Adding a new letter_proofing_data
        _data['letter_proofing_data'].append(
            {
                "verification_code": "secret code",
                "verified": True,
                "verified_by": "eduid-idproofing-letter",
                "created_ts": 'ts',
                "official_address": {
                    "OfficialAddress": {
                        "PostalCode": "12345",
                        "City": "LANDET",
                        "Address2": "ÖRGATAN 79 LGH 10"
                    },
                    "Name": {
                        "Surname": "Testsson",
                        "GivenName": "Testaren Test",
                        "GivenNameMarking": "20"
                    }
                },
                "number": "123456781235",
                "created_by": "eduid-idproofing-letter",
                "verified_ts": 'ts',
                "transaction_id": "debug mode transaction id"
            }
        )
        proofing_user = ProofingUser(data=_data)
        letter_plugin_context.userdb.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
            '$set': {
                'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                "letter_proofing_data": [
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    },
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    }
                ]
            },
            '$unset': {
                'norEduPersonNIN': None
            }
        }

        self.assertDictEqual(
            actual_update,
            expected_update
        )


class AttributeFetcherNINProofingTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherNINProofingTests, self).setUp(celery, get_attribute_manager)
        self.plugin_contexts = [
            oidc_plugin_init(celery.conf),
            letter_plugin_init(celery.conf),
            lookup_mobile_plugin_init(celery.conf)
        ]
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.userdb.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.userdb._drop_whole_collection()
        super(AttributeFetcherNINProofingTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        now = datetime.now(tz=bson.tz_util.FixedOffset(0, 'UTC'))
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
                'created_ts': now
            }],
            'phone': [{
                'verified': True,
                'number': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'nins': [
                            {'number': '123456781235', 'primary': True, 'verified': True}
                        ]
                    },
                    '$unset': {
                        'norEduPersonNIN': None
                    }
                }
            )

    def test_malicious_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True,
            }],
            'malicious': 'hacker',
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
        }

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.userdb._coll.insert(_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'displayName': 'John',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                    },
                    '$unset': {
                        'norEduPersonNIN': None
                    }
                }
            )

    def test_append_attributes_letter_proofing_data(self):
        self.maxDiff = None
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('1' * 24),
                'salt': '456',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
            "letter_proofing_data": [
                {
                    "verification_code": u"secret code",
                    "verified": True,
                    "verified_by": u"eduid-idproofing-letter",
                    "created_ts": u'ts',
                    "official_address": {
                        u"OfficialAddress": {
                            u"PostalCode": u"12345",
                            u"City": u"LANDET",
                            u"Address2": u"ÖRGATAN 79 LGH 10"
                        },
                        u"Name": {
                            u"Surname": u"Testsson",
                            u"GivenName": u"Testaren Test",
                            u"GivenNameMarking": u"20"
                        }
                    },
                    u"number": u"123456781235",
                    u"created_by": u"eduid-idproofing-letter",
                    u"verified_ts": u'ts',
                    u"transaction_id": u"debug mode transaction id"
                }
            ],
        }
        proofing_user = ProofingUser(data=_data)
        letter_plugin_context = letter_plugin_init(celery.conf)
        letter_plugin_context.userdb.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
                    '$set': {
                        'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                        "letter_proofing_data": [
                            {
                                "verification_code": u"secret code",
                                "verified": True,
                                "verified_by": u"eduid-idproofing-letter",
                                "created_ts": u'ts',
                                "official_address": {
                                    u"OfficialAddress": {
                                        u"PostalCode": u"12345",
                                        u"City": u"LANDET",
                                        u"Address2": u"ÖRGATAN 79 LGH 10"
                                    },
                                    u"Name": {
                                        u"Surname": u"Testsson",
                                        u"GivenName": u"Testaren Test",
                                        u"GivenNameMarking": u"20"
                                    }
                                },
                                u"number": u"123456781235",
                                u"created_by": u"eduid-idproofing-letter",
                                u"verified_ts": u'ts',
                                u"transaction_id": u"debug mode transaction id"
                            }
                        ]
                    },
                    '$unset': {
                        'norEduPersonNIN': None
                    }
                }
        self.assertDictEqual(
            actual_update,
            expected_update
        )

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)

        # Don't repeat the letter_proofing_data
        self.assertDictEqual(
            actual_update,
            expected_update
        )

        # Adding a new letter_proofing_data
        _data['letter_proofing_data'].append(
            {
                "verification_code": "secret code",
                "verified": True,
                "verified_by": "eduid-idproofing-letter",
                "created_ts": 'ts',
                "official_address": {
                    "OfficialAddress": {
                        "PostalCode": "12345",
                        "City": "LANDET",
                        "Address2": "ÖRGATAN 79 LGH 10"
                    },
                    "Name": {
                        "Surname": "Testsson",
                        "GivenName": "Testaren Test",
                        "GivenNameMarking": "20"
                    }
                },
                "number": "123456781235",
                "created_by": "eduid-idproofing-letter",
                "verified_ts": 'ts',
                "transaction_id": "debug mode transaction id"
            }
        )
        proofing_user = ProofingUser(data=_data)
        letter_plugin_context.userdb.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
            '$set': {
                'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                "letter_proofing_data": [
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    },
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    }
                ]
            },
            '$unset': {
                'norEduPersonNIN': None
            }
        }

        self.assertDictEqual(
            actual_update,
            expected_update
        )


class AttributeFetcherEmailProofingTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherEmailProofingTests, self).setUp(celery, get_attribute_manager)
        self.plugin_contexts = [
            email_plugin_init(celery.conf),
        ]
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.userdb.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.userdb._drop_whole_collection()
        super(AttributeFetcherEmailProofingTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'phone': [{
                'verified': True,
                'number': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'mailAliases': [{
                            'email': 'john@example.com',
                            'verified': True,
                            'primary': True,
                        }],
                    },
                }
            )

    def test_malicious_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True,
            }],
            'malicious': 'hacker',
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
        }

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.userdb._coll.insert(_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'displayName': 'John',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'mailAliases': [{
                            'email': 'john@example.com',
                            'verified': True,
                            'primary': True
                        }],
                    },
                }
            )


class AttributeFetcherPhoneProofingTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherPhoneProofingTests, self).setUp(celery, get_attribute_manager)
        self.plugin_contexts = [
            phone_plugin_init(celery.conf),
        ]
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.userdb.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.userdb._drop_whole_collection()
        super(AttributeFetcherPhoneProofingTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'phone': [{
                'verified': True,
                'number': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'phone': [{
                            'verified': True,
                            'number': '+46700011336',
                            'primary': True
                        }],
                    },
                }
            )

    def test_malicious_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True,
            }],
            'malicious': 'hacker',
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
        }

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.userdb._coll.insert(_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'displayName': 'John',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=_data)
            context.userdb.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'phone': [{
                            'verified': True,
                            'number': '+46700011336',
                            'primary': True
                        }],
                    },
                }
            )


class AttributeFetcherPersonalDataTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherPersonalDataTests, self).setUp(celery, get_attribute_manager)
        self.plugin_contexts = [
            personal_data_plugin_init(celery.conf),
        ]
        for userdoc in self.amdb._get_all_docs():
            personal_data_user = PersonalDataUser(data=userdoc)
            for context in self.plugin_contexts:
                context.userdb.save(personal_data_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.userdb._drop_whole_collection()
        super(AttributeFetcherPersonalDataTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'phone': [{
                'verified': True,
                'number': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            personal_data_user = PersonalDataUser(data=_data)
            context.userdb.save(personal_data_user)

            self.assertDictEqual(
                attribute_fetcher(context, personal_data_user.user_id),
                {
                    '$set': {
                        'givenName': 'Testaren',
                        'surname': 'Testsson',
                        'displayName': 'Kungen av Kungsan',
                        'preferredLanguage': 'sv',
                    },
                }
            )

    def test_malicious_attributes(self):
        _data = {
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True,
            }],
            'malicious': 'hacker',
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
        }

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.userdb._coll.insert(_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'displayName': 'John',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            personal_data_user = PersonalDataUser(data=_data)
            context.userdb.save(personal_data_user)

            self.assertDictEqual(
                attribute_fetcher(context, personal_data_user.user_id),
                {
                    '$set': {
                        'givenName': 'Testaren',
                        'surname': 'Testsson',
                        'displayName': 'John',
                        'preferredLanguage': 'sv',
                    },
                }
            )


class AttributeFetcherSecurityTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherSecurityTests, self).setUp(celery, get_attribute_manager)
        self.plugin_contexts = [
            security_plugin_init(celery.conf),
        ]
        for userdoc in self.amdb._get_all_docs():
            security_user = SecurityUser(data=userdoc)
            for context in self.plugin_contexts:
                context.userdb.save(security_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.userdb._drop_whole_collection()
        super(AttributeFetcherSecurityTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'displayName': 'Kungen av Kungsan',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'phone': [{
                'verified': True,
                'number': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            security_user = SecurityUser(data=_data)
            context.userdb.save(security_user)

            self.assertDictEqual(
                attribute_fetcher(context, security_user.user_id),
                {
                    '$set': {
                        'passwords': [{
                            'credential_id': u'112345678901234567890123',
                            'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                        }],
                    },
                    '$unset': {
                        'terminated': None
                    }
                }
            )

    def test_malicious_attributes(self):
        _data = {
            'eduPersonPrincipalName': 'test-test',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True,
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True,
            }],
            'malicious': 'hacker',
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
        }

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.userdb._coll.insert(_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        _data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'displayName': 'John',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            security_user = SecurityUser(data=_data)
            context.userdb.save(security_user)

            self.assertDictEqual(
                attribute_fetcher(context, security_user.user_id),
                {
                    '$set': {
                        'passwords': [{
                            'credential_id': u'112345678901234567890123',
                            'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                        }],
                    },
                    '$unset': {
                        'terminated': None
                    }
                }
            )
