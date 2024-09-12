#!/usr/bin/env python3
# Python script to generate a .plist file that launchctl can use to manage opencanary as a service
# as well as bootstrap and bootout scripts to get the service up and running.
# NOTE: Requires homebrew.

import importlib.resources
import json
import pathlib
import plistlib
import re
import stat
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from functools import partial
from os import chmod, pardir, path
from os.path import dirname, join, realpath
from subprocess import CalledProcessError, check_output

OPENCANARY = "opencanary"
LAUNCH_DAEMONS_DIR = "/Library/LaunchDaemons"
DEFAULT_SERVICE_NAME = "com.thinkst.opencanary"
CONFIG_FILE_BASENAME = "opencanary.conf"
DEFAULT_CONFIG_DIR = importlib.resources.files(OPENCANARY).joinpath("data")
USER_CONFIG_FILE = DEFAULT_CONFIG_DIR.joinpath("settings.json")
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR.joinpath(".opencanary.conf")

# opencanary dirs
OPENCANARY_DIR = realpath(join(dirname(__file__), pardir))
OPENCANARY_BIN_DIR = join(OPENCANARY_DIR, "bin")
VENV_DIR = join(OPENCANARY_DIR, "env")
VENV_BIN_DIR = join(VENV_DIR, "bin")
DEFAULT_LOG_DIR = join(OPENCANARY_DIR, "log")

# daemon config
DAEMON_CONFIG_DIR = "/etc/opencanaryd"
DAEMON_CONFIG_PATH = join(DAEMON_CONFIG_DIR, CONFIG_FILE_BASENAME)
DAEMON_PATH = join(VENV_BIN_DIR, "opencanaryd")
DAEMON_RUNTIME_OPTIONS = "--dev"

# This script writes to the launchctl/ folder
LAUNCHCTL_DIR = join(OPENCANARY_DIR, "launchctl")

# Homebrew (TODO: is this necessary?)
try:
    homebrew_bin_dir = join(check_output(["brew", "--prefix"]).decode().rstrip(), "bin")
except CalledProcessError as e:
    print(f"Couldn't get homebrew install location: {e}")
    sys.exit()

# Load opencanary.conf default config
if USER_CONFIG_FILE.exists():
    opencanary_config_file = USER_CONFIG_FILE
else:
    if not DEFAULT_CONFIG_FILE.exists():
        print(
            f"Neither a user 'settings.json' nor a default '.opencanary.conf' found in '{DEFAULT_CONFIG_DIR}'!"
        )
        print("Exiting...")
        sys.exit()

    opencanary_config_file = DEFAULT_CONFIG_FILE
    print("Using default config file......")
    print(
        f"(Create a file at '{USER_CONFIG_FILE}' for individual settings beyond the command line arguments)"
    )

print(f"\nUsing base configuration file: '{opencanary_config_file}'")

with importlib.resources.as_file(opencanary_config_file) as config_file:
    with open(config_file, "r") as file:
        config = json.load(file)
        canaries = [
            k.split(".")[0] for k in config.keys() if re.match("[a-z]+\\.enabled", k)
        ]


# Parse arguments.
parser = ArgumentParser(
    description="Generate .plist, opencanary.conf, and scripts to bootstrap opencanary as a launchctl daemon.",
    formatter_class=ArgumentDefaultsHelpFormatter,
)

parser.add_argument(
    "--service-name",
    help="string you would like launchctl to use as the name of the opencanary service",
    metavar="NAME",
    default=DEFAULT_SERVICE_NAME,
)

parser.add_argument(
    "--log-output-dir",
    help="opencanary will write its logs to files in DIR when the service is running",
    metavar="DIR",
    default=DEFAULT_LOG_DIR,
)

parser.add_argument(
    "--canary",
    action="append",
    help="enable canary service in the generated opencanary.conf file "
    + "(can be supplied more than once)",
    choices=canaries,
    dest="canaries",
)


args = parser.parse_args()
args.canaries = args.canaries or []
plist_basename = args.service_name + ".plist"

# Setup dirs
for dir in [LAUNCHCTL_DIR, args.log_output_dir]:
    print(f"Creating '{dir}'...")
    pathlib.Path(dir).mkdir(parents=True, exist_ok=True)

# File builders
build_launchctl_dir_path = partial(join, LAUNCHCTL_DIR)
build_logfile_name = lambda log_name: join(  # noqa: E731
    args.log_output_dir, f"opencanary.{log_name}.log"
)


# daemon launcher script
launcher_script = build_launchctl_dir_path(f"launch_{args.service_name}.sh")

with open(launcher_script, "w") as file:
    file.write(f'. "{VENV_BIN_DIR}/activate"\n')
    file.write(f'"{DAEMON_PATH}" {DAEMON_RUNTIME_OPTIONS}\n')


# Write launchctl service .plist
plist_output_file = build_launchctl_dir_path(plist_basename)

plist_contents = {
    "Label": args.service_name,
    "RunAtLoad": True,
    "KeepAlive": True,
    "WorkingDirectory": VENV_BIN_DIR,
    "StandardOutPath": build_logfile_name("err"),
    "StandardErrorPath": build_logfile_name("out"),
    "EnvironmentVariables": {
        "PATH": f"{VENV_BIN_DIR}:{homebrew_bin_dir}:/usr/bin:/bin",
        "VIRTUAL_ENV": VENV_DIR,
    },
    "ProgramArguments": [launcher_script],
}

with open(plist_output_file, "wb+") as _plist_file:
    plistlib.dump(plist_contents, _plist_file)


# opencanary config
for canary in canaries:
    config[f"{canary}.enabled"] = canary in args.canaries

log_handlers = config["logger"]["kwargs"]["handlers"]
log_handlers["file"]["filename"] = build_logfile_name("run")

# TODO: This config doesn't work even though direct calls to syslog do
# log_handlers["syslog-unix"] = {
#     "class": "logging.handlers.SysLogHandler",
#     "formatter":"syslog_rfc",
#     "address": [
#         "localhost",
#         514
#     ],
#     "socktype": "ext://socket.SOCK_DGRAM"
# }

config_output_file = build_launchctl_dir_path(CONFIG_FILE_BASENAME)

with open(config_output_file, "w") as file:
    file.write(json.dumps(config, indent=4))


# service bootstrap script
install_service_script = build_launchctl_dir_path(
    f"install_service_{args.service_name}.sh"
)
daemon_plist_path = join(LAUNCH_DAEMONS_DIR, plist_basename)

with open(install_service_script, "w") as file:
    script_contents = [
        f"set -e\n\n" f"chown root '{launcher_script}'",
        f"mkdir -p '{DAEMON_CONFIG_DIR}'",
        f"cp '{config_output_file}' {DAEMON_CONFIG_PATH}",
        f"cp '{plist_output_file}' {LAUNCH_DAEMONS_DIR}",
        f"launchctl bootstrap system '{daemon_plist_path}'",
        "",
    ]

    file.write("\n".join(script_contents))


# uninstall/bootout script
uninstall_service_script = build_launchctl_dir_path(
    f"uninstall_service_{args.service_name}.sh"
)

with open(uninstall_service_script, "w") as file:
    file.write(f"launchctl bootout system/{args.service_name}\n")


# Set permissions
chmod(launcher_script, stat.S_IRWXU)  # stat.S_IEXEC | stat.S_IREAD
chmod(uninstall_service_script, stat.S_IRWXU)
chmod(install_service_script, stat.S_IRWXU)


# Print results
print("Generated files...\n")
print(f"    Service definition: ./{path.relpath(plist_output_file)}")
print(f"       Launcher script: ./{path.relpath(launcher_script)}")
print(f"      Bootstrap script: ./{path.relpath(install_service_script)}")
print(f"        Bootout script: ./{path.relpath(uninstall_service_script)}\n")
print(f"                Config: ./{path.relpath(config_output_file)}")
print(
    f"      Enabled canaries: {', '.join(args.canaries) if args.canaries else 'Nothing enabled!'}\n"
)
print(f"To install as a system service run:\n    'sudo {install_service_script}'\n")
