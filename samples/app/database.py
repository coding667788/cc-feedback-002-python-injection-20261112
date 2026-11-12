import sqlite3

from . import models as mdl


def open_connection(path):
    return sqlite3.connect(path)


def search_users_unsafe(connection, name_fragment):
    # Vulnerable: query string is built by concatenation.
    sql = "SELECT * FROM users WHERE name = '" + name_fragment + "'"
    return connection.execute(sql)


def search_users_safe(connection, name_fragment):
    # Safe: fixed SQL with a bound parameter must not be reported.
    return connection.execute(
        "SELECT * FROM users WHERE name = ?", (name_fragment,)
    )


def load_by_identifier(connection, identifier):
    # Safe after a successful int() -> str() decimal conversion.
    numeric = int(identifier)
    rendered = str(numeric)
    return connection.execute("SELECT * FROM users WHERE id = " + rendered)


def load_by_identifier_failover(connection, identifier):
    # The except branch keeps the original raw string and must be reported.
    try:
        numeric = int(identifier)
        rendered = str(numeric)
    except ValueError:
        rendered = identifier
    return connection.execute("SELECT * FROM users WHERE id = " + rendered)


def insert_model_fields(connection, payload):
    # Field-sensitive: only payload.name is concatenated.
    connection.execute("SELECT * FROM users WHERE name = '" + payload["name"] + "'")
    connection.execute(
        "SELECT * FROM users WHERE code = ?", (payload["code"],)
    )


def read_object_field(connection, account):
    # Attribute-based field sensitivity via a fixed object.
    return connection.execute(
        "SELECT * FROM accounts WHERE id = '" + account.account_id + "'"
    )


def aliased_module_call(connection, keyword):
    return mdl.compose_where(keyword)
