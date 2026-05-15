import json
import time

LOG_PATH = "/var/tmp/opencanary.log"


def get_last_log():
    """
    Gets the last line from the log file as a dictionary
    """
    return get_last_n_logs(1)[0]


def get_last_n_logs(n):
    """
    Reads the last 'n' lines from the log file and returns them as a list of dictionaries.
    """
    with open(LOG_PATH, "r") as file:
        lines = file.readlines()

    last_n_lines = lines[-n:]
    deserialized_data = [json.loads(line) for line in last_n_lines]
    return deserialized_data


def get_log_count():
    with open(LOG_PATH, "r") as file:
        return len(file.readlines())


def get_logs_after(start_line):
    with open(LOG_PATH, "r") as file:
        lines = file.readlines()[start_line:]

    parsed_logs = []
    for line in lines:
        try:
            parsed_logs.append(json.loads(line))
        except json.JSONDecodeError:
            # The log file may be read while a line is still being written.
            # Ignore incomplete/malformed lines and continue scanning.
            continue

    return parsed_logs


def get_matching_log(start_line, predicate):
    for _ in range(10):
        for log in reversed(get_logs_after(start_line)):
            if predicate(log):
                return log
        time.sleep(0.1)

    return None
