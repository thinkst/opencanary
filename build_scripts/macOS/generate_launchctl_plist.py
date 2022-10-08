#!/usr/bin/env python3
# Python script to generate a .plist file that launchctl can use to manage opencanary as a service
# as well as bootstrap and bootout scripts to get the service up and running.
# Requires homebrew

import plistlib
from shutil import copyfile
import stat
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from os import chmod, pardir, path
from pkg_resources import resource_filename
from subprocess import CalledProcessError, check_output

DEFAULT_SERVICE_NAME = 'com.thinkst.opencanary'
DEFAULT_SETTINGS_DIR = '/etc/opencanaryd'
LAUNCH_DAEMONS_DIR = '/Library/LaunchDaemons'
RUNTIME_OPTIONS = "--dev"
DEFAULT_CONFIG_PATH = resource_filename('opencanary', 'data/settings.json')

# Opencanary paths
OPENCANARY_BUILD_SCRIPTS_DIR = path.dirname(path.realpath(__file__))
OPENCANARY_DIR = path.abspath(path.join(OPENCANARY_BUILD_SCRIPTS_DIR, pardir, pardir))
OPENCANARY_BIN_DIR = path.join(OPENCANARY_DIR, 'bin')
OPENCANARY_VENV_DIR = path.join(OPENCANARY_DIR, 'env')
OPENCANARY_VENV_BIN_DIR = path.join(OPENCANARY_VENV_DIR, 'bin')
OPENCANARY_DAEMON_PATH = path.join(OPENCANARY_VENV_BIN_DIR, 'opencanaryd')
OPENCANARY_DAEMON_CONFIG_PATH = path.join(OPENCANARY_VENV_BIN_DIR, 'opencanary.conf')

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
plist_basename = args.service_name + ".plist"
launch_daemon_path = path.join(LAUNCH_DAEMONS_DIR, plist_basename)
launcher_script = path.join(OPENCANARY_BIN_DIR, f"launch_{args.service_name}.sh")
bootstrap_service_script = path.join(OPENCANARY_BIN_DIR, f"bootstrap_service_{args.service_name}.sh")
uninstall_service_script = path.join(OPENCANARY_BIN_DIR, f"uninstall_service_{args.service_name}.sh")


# Write the plist and scripts
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
copyfile(DEFAULT_CONFIG_PATH, OPENCANARY_DAEMON_CONFIG_PATH)

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
print(f"Run 'sudo {bootstrap_service_script}' to install as a system service.")
print(f"(Make edits to the deamon's config file ./{path.relpath(OPENCANARY_DAEMON_CONFIG_PATH)})")
