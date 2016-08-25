import datetime

import bson

from eduid_userdb.exceptions import UserDoesNotExist, UserHasUnknownData
from eduid_userdb.testing import MongoTestCase
from eduid_userdb.proofing import ProofingUser
from eduid_proofing_amp import attribute_fetcher, oidc_plugin_init, letter_plugin_init
from eduid_am.celery import celery, get_attribute_manager


TEST_DB_NAME = 'eduid_proofing_test'


class AttributeFetcherTests(MongoTestCase):

    def setUp(self):
        super(AttributeFetcherTests, self).setUp(celery, get_attribute_manager)
        self.oidc_plugin_context = oidc_plugin_init(celery.conf)
        self.letter_plugin_context = letter_plugin_init(celery.conf)

        for userdoc in self.amdb._get_all_docs():
            dashboard_user = ProofingUser(data=userdoc)
            self.plugin_context.userdb.save(dashboard_user, check_sync=False)

        self.maxDiff = None

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            attribute_fetcher(self.oidc_plugin_context, bson.ObjectId('0' * 24))

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
        }
        user = ProofingUser(data=_data)
        self.oidc_plugin_context.userdb.save(user)

        self.assertEqual(
            attribute_fetcher(self.oidc_plugin_context, user.user_id),
            {
                '$set': {
                    'mail': 'john@example.com',
                    'mailAliases': [{
                        'email': 'john@example.com',
                        'verified': True,
                    }],
                    'passwords': [{
                        'id': bson.ObjectId('112345678901234567890123'),
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }],
                    'mobile': [{
                        'verified': True,
                        'mobile': '+46700011336',
                        'primary': True
                    }],
                },
                '$unset': {
                    'norEduPersonNIN': None
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
        # Write bad entry into database
        user_id = self.oidc_plugin_context.userdb._coll.insert(_data)

        with self.assertRaises(UserHasUnknownData):
            attribute_fetcher(self.oidc_plugin_context, user_id)

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
        }

        user = ProofingUser(data = _data)
        self.oidc_plugin_context.userdb.save(user)

        self.assertEqual(
            attribute_fetcher(self.oidc_plugin_context, user.user_id),
            {
                '$set': {
                    'mail': 'john@example.com',
                    'mailAliases': [{
                        'email': 'john@example.com',
                        'verified': True,
                    }],
                    'displayName': 'John',
                    'passwords': [{
                        'id': bson.ObjectId('112345678901234567890123'),
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }],
                    'mobile': [{
                        'verified': True,
                        'mobile': '+46700011336',
                        'primary': True
                    }],
                },
                '$unset': {
                    'norEduPersonNIN': None
                }
            }
        )

        _data['displayName'] = 'John2'
        user = ProofingUser(data = _data)
        self.oidc_plugin_context.userdb.save(user)

        self.assertEqual(
            attribute_fetcher(self.oidc_plugin_context,
                              user.user_id)['$set']['displayName'],
            'John2',
        )

    def test_append_attributes(self):
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
            }]
        }
        user = ProofingUser(data = _data)
        self.oidc_plugin_context.userdb.save(user)

        actual_update = attribute_fetcher(self.oidc_plugin_context, user.user_id)
        expected_update = {
            '$set': {
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
                              'salt': u'456',
                              }]
            },
            '$unset': {
                'norEduPersonNIN': None
            }
        }
        self.assertEqual(
            actual_update,
            expected_update
        )

        actual_update = attribute_fetcher(self.oidc_plugin_context, user.user_id)
        expected_update = {
            '$set': {
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
                    'salt': u'456',
                }]
            },
            '$unset': {
                'norEduPersonNIN': None
            }
        }
        # Don't repeat the password
        self.assertEqual(
            actual_update,
            expected_update
        )

        # Adding a new password
        _data['passwords'].append(
                {
                    'id': bson.ObjectId('2' * 24),
                    'salt': '456',
                }
        )
        user = ProofingUser(data = _data)
        self.oidc_plugin_context.dashboard_userdb.save(user)

        actual_update = attribute_fetcher(self.oidc_plugin_context, user.user_id)
        expected_update = {
            '$set': {
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
                    'salt': u'456',
                }, {
                    'id': bson.ObjectId('2' * 24),
                    'salt': u'456',
                }]
            },
            '$unset': {
                'norEduPersonNIN': None
            }
        }

        self.assertEqual(
            actual_update,
            expected_update
        )

    def test_NIN_normalization(self):
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
            'norEduPersonNIN': [u'123456781235'],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
        }
        user = ProofingUser(data = _data)
        self.oidc_plugin_context.dashboard_userdb.save(user)
        # Test that the verified NIN is returned in a list
        attributes = attribute_fetcher(self.oidc_plugin_context, user.user_id)
        self.assertEqual(
            attributes,
            {
                '$set': {
                    'mail': 'john@example.com',
                    'mailAliases': [{'email': 'john@example.com', 'verified': True}],
                    'mobile': [{'verified': True, 'mobile': '+46700011336', 'primary': True}],
                    'norEduPersonNIN': ['123456781235'],
                    'passwords': [{
                        'id': bson.ObjectId('112345678901234567890123'),
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }],
                }
            }
        )

