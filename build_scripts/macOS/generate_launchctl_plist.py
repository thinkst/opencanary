#!/usr/bin/env python3
# Python script to generate a .plist file that launchctl can use to manage opencanary as a service
# as well as bootstrap and bootout scripts to get the service up and running.
# Requires homebrew

import plistlib
import stat
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from os import chmod, pardir, path
from subprocess import CalledProcessError, check_output

DEFAULT_SERVICE_NAME = 'com.thinkst.opencanary'
LAUNCH_DAEMONS_DIR = '/Library/LaunchDaemons'

# Opencanary paths
OPENCANARY_BUILD_SCRIPTS_DIR = path.dirname(path.realpath(__file__))
OPENCANARY_DIR = path.abspath(path.join(OPENCANARY_BUILD_SCRIPTS_DIR, pardir, pardir))
OPENCANARY_BIN_DIR = path.join(OPENCANARY_DIR, 'bin')
OPENCANARY_VENV_DIR = path.join(OPENCANARY_DIR, 'env')
OPENCANARY_VENV_BIN_DIR = path.join(OPENCANARY_VENV_DIR, 'bin')
OPENCANARY_START_CMD="opencanaryd --dev"

# Homebrew
try:
    HOMEBREW_DIR = check_output(['brew', '--prefix']).decode()
    HOMEBREW_BIN_DIR = path.join(HOMEBREW_DIR, 'bin')
except CalledProcessError as e:
    print(f"Couldn't get homebrew install location: {e}")
    sys.exit()


# Parse arguments
parser = ArgumentParser(
    description='Generate .plist file launchctl can use to run opencanary as a daemon.',
    formatter_class=ArgumentDefaultsHelpFormatter
)

parser.add_argument(
    '--service-name',
    default=DEFAULT_SERVICE_NAME,
    help='name of the service you would like to run opencanary as')

parser.add_argument(
    '--log-output-dir',
    metavar='DIR',
    help='directory opencanary should write its logs to when the service is running',
    default=OPENCANARY_DIR)

parser.add_argument(
    '--write-launchdaemon',
    default=False,
    action='store_true',
    help=f'write directly to {LAUNCH_DAEMONS_DIR} instead of to {OPENCANARY_DIR} (IMPORTANT: requires sudo)')

args = parser.parse_args()


# Write .plist, write start/stop scripts
plist_basename = args.service_name + ".plist"
launch_daemon_path = path.join(LAUNCH_DAEMONS_DIR, plist_basename)
bootstrap_service_script = path.join(OPENCANARY_BIN_DIR, f"bootstrap_service_{args.service_name}.sh")
bootout_service_script = path.join(OPENCANARY_BIN_DIR, f"bootout_service_{args.service_name}.sh")

launchctl_instructions = {
    'Label': args.service_name,
    'RunAtLoad': True,
    'KeepAlive': True,
    'WorkingDirectory': OPENCANARY_DIR,
    'StandardOutPath':  path.join(args.log_output_dir, 'opencanary.err.log'),
    'StandardErrorPath': path.join(args.log_output_dir, 'opencanary.out.log'),
    'EnvironmentVariables': {
        'PATH': f"{OPENCANARY_VENV_BIN_DIR}:{HOMEBREW_BIN_DIR}:/usr/bin:/bin",
        'VIRTUAL_ENV': OPENCANARY_VENV_DIR
    },
    'ProgramArguments': OPENCANARY_START_CMD.split()
}


if args.write_launchdaemon:
    service_plist_path = path.join(LAUNCH_DAEMONS_DIR, plist_basename)
else:
    service_plist_path = path.join(OPENCANARY_DIR, plist_basename)


with open(service_plist_path, 'wb+') as _plist_file:
    plistlib.dump(launchctl_instructions, _plist_file)
with open(bootstrap_service_script, 'w') as file:
    file.write(f'cp "{service_plist_path}" {LAUNCH_DAEMONS_DIR}\n')
    file.write(f"launchctl bootstrap system '{launch_daemon_path}'\n")
with open(bootout_service_script, 'w') as file:
    file.write(f"launchctl bootout system/{args.service_name}\n")

chmod(bootout_service_script, stat.S_IRWXU)
chmod(bootstrap_service_script, stat.S_IRWXU)

print("Generated files...\n")
print(f"   Service .plist file: '{service_plist_path}'")
print(f"      Bootstrap script: '{bootstrap_service_script}'")
print(f"        Bootout script: '{bootout_service_script}'\n")
