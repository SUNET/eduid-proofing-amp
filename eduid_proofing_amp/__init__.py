from datetime import datetime
from eduid_userdb.util import UTC
from eduid_userdb.proofing import OidcProofingUserDB, LetterProofingUserDB
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
        verified = item.get('verfied', False)
        if verified and type(verified) == bool:  # Be sure that it's not something else that evaluates as True in Python
            result.append(item['nin'])
    return result


class OidcProofingAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri, new_user_date):
        self.userdb = OidcProofingUserDB(db_uri)
        self.new_user_date = datetime.strptime(new_user_date, '%Y-%m-%d').replace(tzinfo=UTC())
        self.WHITELIST_SET_ATTRS = (
            # TODO: Arrays must use put or pop, not set, but need more deep refacts
            'norEduPersonNIN',  # Old format
            'nins'  # New format
        )
        self.WHITELIST_UNSET_ATTRS = (
            'norEduPersonNIN'
        )


class LetterProofingAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri, new_user_date):
        self.userdb = LetterProofingUserDB(db_uri)
        self.new_user_date = datetime.strptime(new_user_date, '%Y-%m-%d').replace(tzinfo=UTC())
        self.WHITELIST_SET_ATTRS = (
            # TODO: Arrays must use put or pop, not set, but need more deep refacts
            'norEduPersonNIN',  # Old format
            'nins',  # New format
            'letter_proofing_data',
        )
        self.WHITELIST_UNSET_ATTRS = (
            'norEduPersonNIN',
        )

# TODO: PhoneProofingAMPContex and MailAliasesProofingAMPContext


def oidc_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: OidcProofingAMPContext
    """
    return OidcProofingAMPContext(am_conf['MONGO_URI'], am_conf['NEW_USER_DATE'])


def letter_plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: LetterProofingAMPContext
    """
    return LetterProofingAMPContext(am_conf['MONGO_URI'], am_conf['NEW_USER_DATE'])


def attribute_fetcher(context, user_id):
    """
    Read a user from the Dashboard private userdb and return an update
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
    logger.debug('Trying to get user with _id: {} from {}.'.format(user_id, context.userdb))
    user = context.userdb.get_user_by_id(user_id)
    logger.debug('User: {} found.'.format(user))

    old_userdb_format = True
    # Save users created after or on new_user_date in the new format
    primary_mail_ts = user.mail_addresses.primary.created_ts
    if primary_mail_ts and primary_mail_ts >= context.new_user_date:
        old_userdb_format = False
    # Always use new users for the following tests users
    # ft:staging, ft:prod, lundberg:staging, lundberg:prod, john:staging, john:prod
    elif user.eppn in ['vofaz-tajod', 'takaj-sosup', 'tovuk-zizih', 'rubom-lujov', 'faraf-livok', 'hofij-zanok']:
        old_userdb_format = False

    user_dict = user.to_dict(old_userdb_format)  # Do not try to save new format for other users

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
