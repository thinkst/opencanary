#!/usr/bin/env python3
# Python script to generate a .plist file that launchctl can use to manage opencanary as a service
# as well as bootstrap and bootout scripts to get the service up and running.
# NOTE: Requires homebrew.

import json
import plistlib
import re
import stat
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from os import chmod, pardir, path
from shutil import copyfile
from subprocess import CalledProcessError, check_output

from pkg_resources import resource_filename

DEFAULT_SERVICE_NAME = 'com.thinkst.opencanary'
DEFAULT_SETTINGS_DIR = '/etc/opencanaryd'
LAUNCH_DAEMONS_DIR = '/Library/LaunchDaemons'
RUNTIME_OPTIONS = "--dev"

# Opencanary paths (_PATH for files, _DIR for dirs)
OPENCANARY_BUILD_SCRIPTS_DIR = path.dirname(path.realpath(__file__))
OPENCANARY_DIR = path.abspath(path.join(OPENCANARY_BUILD_SCRIPTS_DIR, pardir, pardir))
OPENCANARY_BIN_DIR = path.join(OPENCANARY_DIR, 'bin')
OPENCANARY_VENV_DIR = path.join(OPENCANARY_DIR, 'env')
OPENCANARY_VENV_BIN_DIR = path.join(OPENCANARY_VENV_DIR, 'bin')
OPENCANARY_DAEMON_PATH = path.join(OPENCANARY_VENV_BIN_DIR, 'opencanaryd')
OPENCANARY_DAEMON_CONFIG_PATH = path.join(OPENCANARY_VENV_BIN_DIR, 'opencanary.conf')
DEFAULT_CONFIG_PATH = resource_filename('opencanary', 'data/settings.json')

with open(DEFAULT_CONFIG_PATH, 'r') as file:
    daemon_config = json.load(file)

# Homebrew (TODO: is this necessary?)
try:
    HOMEBREW_DIR = check_output(['brew', '--prefix']).decode()
    HOMEBREW_BIN_DIR = path.join(HOMEBREW_DIR, 'bin')
except CalledProcessError as e:
    print(f"Couldn't get homebrew install location: {e}")
    sys.exit()


# Parse arguments
DESCRIPTION = 'Generate .plist, opencanary.conf, and scripts to bootstrap opencanary as a launchctl daemon.'
SERVICES = [k.split(".")[0] for k in daemon_config.keys() if re.match("[a-z]+\\.enabled", k)]

parser = ArgumentParser(
    description=DESCRIPTION,
    formatter_class=ArgumentDefaultsHelpFormatter
)

parser.add_argument('--service-name',
                    help='string you would like launchctl to use as the name of the opencanary service',
                    metavar='NAME',
                    default=DEFAULT_SERVICE_NAME)

parser.add_argument('--log-output-dir',
                    help='opencanary will write its logs to files in DIR when the service is running',
                    metavar='DIR',
                    default=OPENCANARY_DIR)

parser.add_argument('--write-launchdaemon', action='store_true',
                    help=f'write directly to {LAUNCH_DAEMONS_DIR} (requires sudo)')

parser.add_argument('--canary', action='append',
                    help=f'enable canary service in the generated opencanary.conf file ' + \
                         '(can be supplied more than once)',
                    choices=SERVICES,
                    dest='services')


args = parser.parse_args()
args.services = args.services or []

# Files
plist_basename = args.service_name + ".plist"
launch_daemon_path = path.join(LAUNCH_DAEMONS_DIR, plist_basename)
launcher_script = path.join(OPENCANARY_BIN_DIR, f"launch_{args.service_name}.sh")
bootstrap_service_script = path.join(OPENCANARY_BIN_DIR, f"bootstrap_service_{args.service_name}.sh")
uninstall_service_script = path.join(OPENCANARY_BIN_DIR, f"uninstall_service_{args.service_name}.sh")


# Write the plist, scripts, and config
launchctl_instructions = {
    'Label': args.service_name,
    'RunAtLoad': True,
    'KeepAlive': True,
    'WorkingDirectory': OPENCANARY_VENV_BIN_DIR,
    'StandardOutPath':  path.join(args.log_output_dir, 'opencanary.err.log'),
    'StandardErrorPath': path.join(args.log_output_dir, 'opencanary.out.log'),
    'EnvironmentVariables': {
        'PATH': f"{OPENCANARY_VENV_BIN_DIR}:{HOMEBREW_BIN_DIR}:/usr/bin:/bin",
        'VIRTUAL_ENV': OPENCANARY_VENV_DIR
    },
    'ProgramArguments': [launcher_script]
}

if args.write_launchdaemon:
    service_plist_path = path.join(LAUNCH_DAEMONS_DIR, plist_basename)
else:
    service_plist_path = path.join(OPENCANARY_DIR, plist_basename)

# plist
with open(service_plist_path, 'wb+') as _plist_file:
    plistlib.dump(launchctl_instructions, _plist_file)

# Launcher script
with open(launcher_script, 'w') as file:
    file.write(f'. "{OPENCANARY_VENV_BIN_DIR}/activate"\n')
    file.write(f'"{OPENCANARY_DAEMON_PATH}" {RUNTIME_OPTIONS}\n')

# bootstrap script
with open(bootstrap_service_script, 'w') as file:
    #file.write(f'mkdir -p "{DEFAULT_SETTINGS_DIR}"')
    file.write(f'chown root "{launcher_script}"\n')
    file.write(f'cp "{service_plist_path}" {LAUNCH_DAEMONS_DIR}\n')
    file.write(f"launchctl bootstrap system '{launch_daemon_path}'\n")

# uninstall/bootout script
with open(uninstall_service_script, 'w') as file:
    file.write(f"launchctl bootout system/{args.service_name}\n")

# settings
for service in args.services:
    daemon_config[f"{service}.enabled"] = True

with open(OPENCANARY_DAEMON_CONFIG_PATH, 'w') as config_file:
    config_file.write(json.dumps(daemon_config, indent=4))

# Set permissions
chmod(launcher_script, stat.S_IRWXU)  # stat.S_IEXEC | stat.S_IREAD
chmod(uninstall_service_script, stat.S_IRWXU)
chmod(bootstrap_service_script, stat.S_IRWXU)


# Print results
print("Generated files...\n")
print(f"    Service definition: ./{path.relpath(service_plist_path)}")
print(f"       Launcher script: ./{path.relpath(launcher_script)}")
print(f"      Bootstrap script: ./{path.relpath(bootstrap_service_script)}")
print(f"        Bootout script: ./{path.relpath(uninstall_service_script)}\n")
print(f"                Config: ./{path.relpath(OPENCANARY_DAEMON_CONFIG_PATH)}")
print(f"      Enabled services: {', '.join(args.services)}\n")
print(f"Run 'sudo {bootstrap_service_script}' to install as a system service.")
print(f"(Make edits to the deamon's config file )")
