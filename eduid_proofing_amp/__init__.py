from __future__ import absolute_import

from eduid_userdb.proofing import OidcProofingUserDB, LetterProofingUserDB, LookupMobileProofingUserDB
from eduid_userdb.proofing import EmailProofingUserDB, PhoneProofingUserDB, OrcidProofingUserDB
from eduid_userdb.proofing import EidasProofingUserDB
from eduid_userdb.personal_data import PersonalDataUserDB
from eduid_userdb.security import SecurityUserDB
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def value_filter(attr, value):
    if value:
        # Check it we need to filter values for this attribute
        #if attr == 'norEduPersonNIN':
        #   value = filter_nin(value)
        pass
    return value


def filter_nin(value):
    """
    :param value: dict
    :return: list

    This function will compile a users verified NINs to a list of strings.
    """
    result = []
    for item in value:
        verified = item.get('verified', False)
        if verified and type(verified) == bool:  # Be sure that it's not something else that evaluates as True in Python
            result.append(item['nin'])
    return result


class OidcProofingAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = OidcProofingUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            # TODO: Arrays must use put or pop, not set, but need more deep refacts
            'nins',  # New format
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'norEduPersonNIN',
            'nins'  # New format
        ]


class LetterProofingAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = LetterProofingUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            # TODO: Arrays must use put or pop, not set, but need more deep refacts
            'nins',  # New format
            'letter_proofing_data',
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'norEduPersonNIN',
            'nins'  # New format
        ]


class LookupMobileProofingAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = LookupMobileProofingUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            # TODO: Arrays must use put or pop, not set, but need more deep refacts
            'nins',  # New format
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'norEduPersonNIN',
            'nins'  # New format
        ]


class EmailProofingAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = EmailProofingUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            # TODO: Arrays must use put or pop, not set, but need more deep refacts
            'mailAliases',
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'mailAliases',
        ]


class PhoneProofingAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = PhoneProofingUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            # TODO: Arrays must use put or pop, not set, but need more deep refacts
            'phone',
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'phone',
        ]


class PersonalDataAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = PersonalDataUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            'givenName',
            'surname',  # New format
            'displayName',
            'preferredLanguage',
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'sn',  # Old format
        ]


class SecurityAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = SecurityUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            'passwords',
            'terminated',
            'nins',             # For AL1 downgrade on password reset
            'phone',            # For AL1 downgrade on password reset
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'passwords',
            'terminated',
            'norEduPersonNIN',  # For AL1 downgrade on password reset
            'nins',             # For AL1 downgrade on password reset
            'phone',            # For AL1 downgrade on password reset
        ]


class OrcidAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = OrcidProofingUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            'orcid',
        ]
        self.WHITELIST_UNSET_ATTRS = [
            'orcid',
        ]


class EidasAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.private_db = EidasProofingUserDB(db_uri)
        self.WHITELIST_SET_ATTRS = [
            'passwords',
        ]
        self.WHITELIST_UNSET_ATTRS = []


def oidc_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: OidcProofingAMPContext
    """
    return OidcProofingAMPContext(am_conf['MONGO_URI'])


def letter_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: LetterProofingAMPContext
    """
    return LetterProofingAMPContext(am_conf['MONGO_URI'])


def lookup_mobile_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: LetterProofingAMPContext
    """
    return LookupMobileProofingAMPContext(am_conf['MONGO_URI'])


def email_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: EmailProofingAMPContext
    """
    return EmailProofingAMPContext(am_conf['MONGO_URI'])


def phone_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: PhoneProofingAMPContext
    """
    return PhoneProofingAMPContext(am_conf['MONGO_URI'])


def personal_data_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: PersonalDataAMPContext
    """
    return PersonalDataAMPContext(am_conf['MONGO_URI'])


def security_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: SecurityAMPContext
    """
    return SecurityAMPContext(am_conf['MONGO_URI'])


def orcid_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: OrcidAMPContext
    """
    return OrcidAMPContext(am_conf['MONGO_URI'])


def eidas_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: EidasAMPContext
    """
    return EidasAMPContext(am_conf['MONGO_URI'])


def attribute_fetcher(context, user_id):
    """
    Read a user from the Dashboard private private_db and return an update
    dict to let the Attribute Manager update the use in the central
    eduid user database.

    :param context: Plugin context, see plugin_init above.
    :param user_id: Unique identifier

    :type context: DashboardAMPContext
    :type user_id: ObjectId

    :return: update dict
    :rtype: dict
    """

    attributes = {}
    logger.debug('Trying to get user with _id: {} from {}.'.format(user_id, context.private_db))
    user = context.private_db.get_user_by_id(user_id)
    logger.debug('User: {} found.'.format(user))

    user_dict = user.to_dict(old_userdb_format=False)

    # white list of valid attributes for security reasons
    attributes_set = {}
    attributes_unset = {}
    for attr in context.WHITELIST_SET_ATTRS:
        value = value_filter(attr, user_dict.get(attr, None))
        if value:
            attributes_set[attr] = value
        elif attr in context.WHITELIST_UNSET_ATTRS:
            attributes_unset[attr] = value

    logger.debug('Will set attributes: {}'.format(attributes_set))
    logger.debug('Will remove attributes: {}'.format(attributes_unset))

    if attributes_set:
        attributes['$set'] = attributes_set
    if attributes_unset:
        attributes['$unset'] = attributes_unset

    return attributes
