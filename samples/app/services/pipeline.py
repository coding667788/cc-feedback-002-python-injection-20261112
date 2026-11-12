import subprocess


def stage_one(value):
    prepared = "job-" + value
    return stage_two(prepared)


def stage_two(prepared):
    normalised = prepared.strip()
    return stage_three(normalised)


def stage_three(normalised):
    # Four frames deep from the route (route -> one -> two -> three).
    return subprocess.run("echo " + normalised, shell=True)
