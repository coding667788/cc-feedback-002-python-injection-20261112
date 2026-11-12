class Account:
    def __init__(self, account_id, display_name):
        self.account_id = account_id
        self.display_name = display_name


def make_account(account_id, display_name):
    return Account(account_id, display_name)


def compose_where(keyword):
    return "name LIKE '%" + keyword + "%'"
