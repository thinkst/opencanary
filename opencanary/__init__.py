import os
import subprocess

__version__ = "0.9.4"

from os import PathLike
from typing import Union

BIN_LOCATIONS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]


def _check_file_exists_and_executable(path: Union[PathLike, str]) -> bool:
    if not os.path.isfile(path):
        return False
    else:
        return os.access(path, os.X_OK)


def safe_exec(binary_name: str, args: list) -> bytes:
    """
    Executes the given binary with the given arguments as a subprocess. What makes this safe is that the binary name
    is not executed as an alias, and only binaries that live in trusted system locations are executed. This means that
    only system-wide binaries are executable.
    """
    exec_path = None
    for prefix in BIN_LOCATIONS:
        bin_path = os.path.join(prefix, binary_name)
        if _check_file_exists_and_executable(os.path.join(prefix, binary_name)):
            exec_path = bin_path
            break
    if exec_path is None:
        raise Exception(f"Could not find executable ${binary_name}")
    else:
        return subprocess.check_output(args, shell=True, executable=exec_path)
