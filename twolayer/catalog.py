"""Tool catalogue: maps every AgentDojo v1 tool to an environment-neutral category.

Written only from the tool names and descriptions shipped with AgentDojo (Objective 4/5 rule:
no test user tasks or injection tasks are used here).

category      meaning
-----------   ---------------------------------------------------------------
read_private  reads the user's own account data (balance, profile, contacts, own lists)
read_external returns free text written by other people (emails, files, messages,
              calendar descriptions, transaction subjects, reviews) -> untrusted content
read_public   returns structured provider facts (prices, addresses, opening hours, flights)
read_web      fetches a web page at a URL (untrusted content; the URL itself can leak data)
communicate   sends a message or posts content outside the user's account
financial     moves or schedules money
modify        creates or changes items in the user's account (events, files, bookings)
delete        deletes or cancels items
permission    grants or removes access for another person
credential    changes a password
"""

CATEGORIES = ['read_private', 'read_external', 'read_public', 'read_web', 'communicate',
              'financial', 'modify', 'delete', 'permission', 'credential']
READ_CATEGORIES = {'read_private', 'read_external', 'read_public', 'read_web'}
SIDE_EFFECT_CATEGORIES = set(CATEGORIES) - READ_CATEGORIES
UNTRUSTED_CATEGORIES = {'read_external', 'read_web'}

# targets = argument names that hold a recipient, account, e-mail address, user or URL
_C = lambda cat, targets=(): {'category': cat, 'targets': tuple(targets)}

CATALOG = {
    'workspace': {
        'send_email': _C('communicate', ['recipients', 'cc', 'bcc']),
        'delete_email': _C('delete'),
        'get_unread_emails': _C('read_external'),
        'get_sent_emails': _C('read_private'),
        'get_received_emails': _C('read_external'),
        'get_draft_emails': _C('read_private'),
        'search_emails': _C('read_external'),
        'search_contacts_by_name': _C('read_private'),
        'search_contacts_by_email': _C('read_private'),
        'get_current_day': _C('read_private'),
        'search_calendar_events': _C('read_external'),
        'get_day_calendar_events': _C('read_external'),
        'create_calendar_event': _C('modify', ['participants']),
        'cancel_calendar_event': _C('delete'),
        'reschedule_calendar_event': _C('modify'),
        'add_calendar_event_participants': _C('permission', ['participants']),
        'append_to_file': _C('modify'),
        'search_files_by_filename': _C('read_external'),
        'create_file': _C('modify'),
        'delete_file': _C('delete'),
        'get_file_by_id': _C('read_external'),
        'list_files': _C('read_external'),
        'share_file': _C('permission', ['email']),
        'search_files': _C('read_external'),
    },
    'travel': {
        'get_user_information': _C('read_private'),
        'get_all_hotels_in_city': _C('read_public'),
        'get_hotels_prices': _C('read_public'),
        'get_rating_reviews_for_hotels': _C('read_external'),
        'get_hotels_address': _C('read_public'),
        'get_all_restaurants_in_city': _C('read_public'),
        'get_cuisine_type_for_restaurants': _C('read_public'),
        'get_restaurants_address': _C('read_public'),
        'get_rating_reviews_for_restaurants': _C('read_external'),
        'get_dietary_restrictions_for_all_restaurants': _C('read_public'),
        'get_contact_information_for_restaurants': _C('read_public'),
        'get_price_for_restaurants': _C('read_public'),
        'check_restaurant_opening_hours': _C('read_public'),
        'get_all_car_rental_companies_in_city': _C('read_public'),
        'get_car_types_available': _C('read_public'),
        'get_rating_reviews_for_car_rental': _C('read_external'),
        'get_car_fuel_options': _C('read_public'),
        'get_car_rental_address': _C('read_public'),
        'get_car_price_per_day': _C('read_public'),
        'create_calendar_event': _C('modify', ['participants']),
        'search_calendar_events': _C('read_external'),
        'get_day_calendar_events': _C('read_external'),
        'cancel_calendar_event': _C('delete'),
        'reserve_hotel': _C('modify'),
        'reserve_car_rental': _C('modify'),
        'reserve_restaurant': _C('modify'),
        'get_flight_information': _C('read_public'),
        'send_email': _C('communicate', ['recipients', 'cc', 'bcc']),
    },
    'banking': {
        'get_iban': _C('read_private'),
        'send_money': _C('financial', ['recipient']),
        'schedule_transaction': _C('financial', ['recipient']),
        'update_scheduled_transaction': _C('financial', ['recipient']),
        'get_balance': _C('read_private'),
        'get_most_recent_transactions': _C('read_external'),
        'get_scheduled_transactions': _C('read_private'),
        'read_file': _C('read_external'),
        'get_user_info': _C('read_private'),
        'update_password': _C('credential'),
        'update_user_info': _C('modify'),
    },
    'slack': {
        'get_channels': _C('read_private'),
        'add_user_to_channel': _C('permission', ['user']),
        'read_channel_messages': _C('read_external'),
        'read_inbox': _C('read_external'),
        'send_direct_message': _C('communicate', ['recipient']),
        'send_channel_message': _C('communicate'),
        'get_users_in_channel': _C('read_private'),
        'invite_user_to_slack': _C('permission', ['user', 'user_email']),
        'remove_user_from_slack': _C('permission', ['user']),
        'get_webpage': _C('read_web', ['url']),
        'post_webpage': _C('communicate', ['url']),
    },
}

# words in a user request that show the user asked for an action of this category
# (taken from the tool descriptions and common phrasing; used for the request-alignment feature)
ACTION_WORDS = {
    'communicate': ['send', 'email', 'e-mail', 'mail', 'message', 'reply', 'forward', 'tell', 'post', 'notify',
                    'inform', 'write to', 'dm', 'share', 'invite'],
    'financial': ['pay', 'send', 'transfer', 'payment', 'transaction', 'refund', 'money', 'schedule', 'rent',
                  'bill', 'amount', 'recurring'],
    'modify': ['create', 'add', 'book', 'reserve', 'reservation', 'schedule', 'update', 'change', 'append',
               'reschedule', 'move', 'make', 'organize', 'organise', 'set up', 'save', 'file', 'event',
               'calendar', 'address'],
    'delete': ['delete', 'remove', 'cancel', 'clear', 'erase'],
    'permission': ['invite', 'add', 'share', 'remove', 'grant', 'access', 'participant', 'kick'],
    'credential': ['password'],
    'read_web': ['website', 'webpage', 'web page', 'url', 'link', 'visit', 'www', 'http', 'blog', 'article'],
}


def tool_info(suite: str, tool: str) -> dict:
    """Return the catalogue entry; unknown tools are treated as 'modify' (side effect, no targets)."""
    return CATALOG.get(suite, {}).get(tool, {'category': 'modify', 'targets': ()})
