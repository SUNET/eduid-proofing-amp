# -*- coding: utf-8 -*-

import datetime
import bson

from eduid_userdb.exceptions import UserDoesNotExist, UserHasUnknownData
from eduid_userdb.testing import MongoTestCase
from eduid_userdb.proofing import ProofingUser
from eduid_proofing_amp import attribute_fetcher, oidc_plugin_init, letter_plugin_init
from eduid_am.celery import celery, get_attribute_manager


class AttributeFetcherTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherTests, self).setUp(celery, get_attribute_manager)
        self.plugin_contexts = [
            oidc_plugin_init(celery.conf),
            letter_plugin_init(celery.conf)
        ]
        for userdoc in self.amdb._get_all_docs():
            dashboard_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.userdb.save(dashboard_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.userdb._drop_whole_collection()
        super(AttributeFetcherTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        _data = {
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
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'norEduPersonNIN': [u'123456781235'],
        }

        for context in self.plugin_contexts:
            user = ProofingUser(data=_data)
            context.userdb.save(user)

            self.assertEqual(
                attribute_fetcher(context, user.user_id),
                {
                    '$set': {
                        'norEduPersonNIN': [u'123456781235'],
                    }
                }
            )

    def test_malicious_attributes(self):
        _data = {
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
            user = ProofingUser(data=_data)
            context.userdb.save(user)

            self.assertEqual(
                attribute_fetcher(context, user.user_id),
                {
                    '$set': {
                        'norEduPersonNIN': [u'123456781235'],
                    }
                }
            )

    def test_append_attributes_letter_proofing_data(self):
        self.maxDiff = None
        _data = {
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
        user = ProofingUser(data=_data)
        letter_plugin_context = letter_plugin_init(celery.conf)
        letter_plugin_context.userdb.save(user)

        actual_update = attribute_fetcher(letter_plugin_context, user.user_id)
        expected_update = {
                    '$set': {
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
                        ]
                    }
                }
        self.assertEqual(
            actual_update,
            expected_update
        )

        actual_update = attribute_fetcher(letter_plugin_context, user.user_id)

        # Don't repeat the password
        self.assertEqual(
            actual_update,
            expected_update
        )

        # Adding a new password
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
        user = ProofingUser(data=_data)
        letter_plugin_context.userdb.save(user)

        actual_update = attribute_fetcher(letter_plugin_context, user.user_id)
        expected_update = {
            '$set': {
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
            }
        }

        self.assertEqual(
            actual_update,
            expected_update
        )


