import os
import shutil
import subprocess

__version__ = "0.9.5"

STDPATH = os.pathsep.join(["/usr/bin", "/bin", "/usr/sbin", "/sbin"])


def safe_exec(binary_name: str, args: list) -> bytes:
    """
    Executes the given binary with the given arguments as a subprocess. What makes this safe is that the binary name
    is not executed as an alias, and only binaries that live in trusted system locations are executed. This means that
    only system-wide binaries are executable.
    """
    exec_path = shutil.which(binary_name, path=STDPATH)
    if exec_path is None:
        raise Exception(f"Could not find executable ${binary_name} in ${STDPATH}")

    args.insert(0, exec_path)
    return subprocess.check_output(args)
