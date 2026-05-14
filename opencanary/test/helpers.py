import json
import time


LOG_PATH = "/var/tmp/opencanary.log"


def get_log_count():
    with open(LOG_PATH, "r") as file:
        return len(file.readlines())


def get_logs_after(start_line):
    with open(LOG_PATH, "r") as file:
        lines = file.readlines()[start_line:]
    return [json.loads(line) for line in lines]


def get_matching_log(start_line, predicate):
    for _ in range(10):
        for log in reversed(get_logs_after(start_line)):
            if predicate(log):
                return log
        time.sleep(0.1)

    return None
