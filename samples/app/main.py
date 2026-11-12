import sqlite3

from .database import (
    insert_model_fields,
    load_by_identifier,
    load_by_identifier_failover,
    read_object_field,
    search_users_safe,
    search_users_unsafe,
)
from .models import make_account
from .services.commands import (
    branch_dispatch,
    run_report_safe,
    run_report_unsafe,
    sql_via_relative_import,
    three_layer_entry,
)
from .services import pipeline as pl


def get():
    # Stand-in for FastAPI's @app.get decorator; the scanner matches names only.
    def decorator(func):
        return func

    return decorator


@get()
def unsafe_sql_route(keyword: str):
    connection = sqlite3.connect("app.db")
    return search_users_unsafe(connection, keyword)


@get()
def safe_sql_route(keyword: str):
    connection = sqlite3.connect("app.db")
    return search_users_safe(connection, keyword)


@get()
def safe_integer_route(identifier: str):
    connection = sqlite3.connect("app.db")
    return load_by_identifier(connection, identifier)


@get()
def failover_integer_route(identifier: str):
    connection = sqlite3.connect("app.db")
    return load_by_identifier_failover(connection, identifier)


@get()
def field_isolation_route(name: str, code: str):
    connection = sqlite3.connect("app.db")
    payload = {"name": name, "code": code}
    return insert_model_fields(connection, payload)


@get()
def object_field_route(account_id: str, display_name: str):
    connection = sqlite3.connect("app.db")
    account = make_account(account_id, display_name)
    return read_object_field(connection, account)


@get()
def command_unsafe_route(report_name: str):
    return run_report_unsafe(report_name)


@get()
def command_safe_route(report_name: str):
    return run_report_safe(report_name)


@get()
def branch_route(mode: str, user_input: str):
    return branch_dispatch(mode, user_input)


@get()
def deep_chain_route(value: str):
    return three_layer_entry(value)


@get()
def alias_route(keyword: str):
    connection = sqlite3.connect("app.db")
    return sql_via_relative_import(connection, keyword)


@get()
def same_helper_mixed_route(clean_text: str, dirty_text: str):
    connection = sqlite3.connect("app.db")
    safe_result = search_users_safe(connection, clean_text)
    dirty_result = search_users_unsafe(connection, dirty_text)
    return safe_result, dirty_result


@get()
def dynamic_dispatch_route(value: str):
    statements = []
    for index in range(len(value)):
        statements.append(index)
    return statements
