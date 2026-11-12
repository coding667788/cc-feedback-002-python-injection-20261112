import os
import subprocess

from .. import database
from . import pipeline as pipe


def run_report_unsafe(report_name):
    # Vulnerable: shell=True with concatenated command.
    command = "echo report " + report_name
    return subprocess.run(command, shell=True)


def run_report_safe(report_name):
    # Safe: shell=False and a fixed native program with an argument list.
    return subprocess.run(["echo", "report", report_name], shell=False)


def os_system_unsafe(label):
    os.system("logger " + label)


def branch_dispatch(mode, user_input):
    # Mutually exclusive branches must never be merged into one path.
    if mode == "raw":
        command = "echo " + user_input
        subprocess.run(command, shell=True)
    else:
        subprocess.run(["echo", user_input], shell=False)


def three_layer_entry(value):
    return pipe.stage_one(value)


def sql_via_relative_import(connection, keyword):
    return database.search_users_unsafe(connection, keyword)
