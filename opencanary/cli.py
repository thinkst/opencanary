import os
import shutil
import signal
import sys
from importlib.resources import as_file, files
from pathlib import Path
from typing import Annotated

import typer
import errno
from twisted.internet.error import CannotListenError
from twisted.python import usage
from twisted.scripts._twistd_unix import ServerOptions, UnixApplicationRunner

from opencanary import __version__
from opencanary.config import (
    CONFIG_PATH_ENVVAR,
    ConfigLoadError,
    load_config,
    validate_config,
)

CONFIG_DIR = Path.home() / ".opencanary"
CONFIG_NAME = "opencanary.conf"
CONFIG_PATH = CONFIG_DIR / CONFIG_NAME
PIDFILE = CONFIG_DIR / "opencanary.pid"
app = typer.Typer(add_completion=False, no_args_is_help=True)


def _resource_path(name: str):
    return as_file(files("opencanary").joinpath(name))


def _run_twistd(options: list[str]) -> int:
    config = ServerOptions()
    try:
        config.parseOptions(options)
    except usage.error as exc:
        print(exc, file=sys.stderr)
        return 1

    try:
        UnixApplicationRunner(config).run()
    except CannotListenError as exc:
        if getattr(exc.socketError, "errno", None) == errno.EACCES and exc.port is not None and exc.port < 1024:
            print(
                f"Cannot bind to privileged port {exc.port}. Run `sudo opencanary ...` or use a config with ports 1024 and above for development.",
                file=sys.stderr,
            )
            return 1
        raise
    except SystemExit as exc:
        code = exc.code
        print(exc, file=sys.stderr)
        return code if isinstance(code, int) else 1

    return 0


def _prepare_runtime_config(configfile: str | Path = CONFIG_NAME) -> int:
    try:
        config = load_config(configfile)
    except ConfigLoadError as exc:
        print(exc, file=sys.stderr)
        return 1

    errors = validate_config(config)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    if config.source_path is not None:
        os.environ[CONFIG_PATH_ENVVAR] = str(config.source_path)
    return 0


def _read_pid() -> int:
    return int(PIDFILE.read_text().strip())


def _warn_drop_privileges(uid: str | None, gid: str | None) -> None:
    if uid is None or gid is None:
        print(
            "WARNING: OpenCanary will not drop root user or group privileges after launching. "
            "Set both --uid=nobody and --gid=nogroup (or another low privilege user/group) "
            "to silence this warning.",
            file=sys.stderr,
        )


def _twistd_flags(uid: str | None, gid: str | None) -> list[str]:
    flags: list[str] = []
    if uid is not None:
        flags.append(f"--uid={uid}")
    if gid is not None:
        flags.append(f"--gid={gid}")
    return flags


def _start(uid: str | None, gid: str | None, nodaemon: bool) -> int:
    config_status = _prepare_runtime_config()
    if config_status != 0:
        return config_status

    _warn_drop_privileges(uid, gid)
    with _resource_path("opencanary.tac") as tac_path:
        options = ["--python", str(tac_path)]
        if nodaemon:
            options.insert(0, "--nodaemon")
        else:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            options.extend(["--pidfile", str(PIDFILE), "--syslog", "--prefix=opencanary"])
        options.extend(_twistd_flags(uid, gid))
        return _run_twistd(options)


def _copyconfig() -> int:
    destination = CONFIG_PATH
    if destination.exists():
        print(
            f"A config file already exists at {destination}, please move it first"
        )
        return 1

    with _resource_path("data/settings.json") as default_config:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy(default_config, destination)

    print(f"[*] A sample config file is ready {destination}\n")
    print('[*] Edit your configuration, then launch with "opencanary start"')
    return 0


def _usermodule() -> int:
    with _resource_path("data/settings-usermodule.json") as usermod_config:
        current_config = Path(CONFIG_NAME)
        if current_config.exists() and current_config.read_bytes() != Path(
            usermod_config
        ).read_bytes():
            print(f"Backing up old config to {current_config.with_suffix('.conf.old')}")
            shutil.copy(current_config, current_config.with_suffix(".conf.old"))

        shutil.copy(usermod_config, current_config)

    config_status = _prepare_runtime_config(current_config)
    if config_status != 0:
        return config_status

    with _resource_path("opencanary.tac") as tac_path:
        return _run_twistd(["--nodaemon", "--python", str(tac_path)])


def _stop() -> int:
    try:
        pid = _read_pid()
    except FileNotFoundError:
        print(f"PID file not found: {PIDFILE}", file=sys.stderr)
        return 1

    try:
        os.kill(pid, signal.SIGTERM)
    except PermissionError:
        print(
            f"Stopping process {pid} requires sufficient permissions. Run `sudo opencanary stop` if needed.",
            file=sys.stderr,
        )
        return 1
    return 0


def _restart(uid: str | None, gid: str | None) -> int:
    stop_code = _stop()
    if stop_code != 0:
        return stop_code
    return _start(uid, gid, nodaemon=False)


def _version_callback(value: bool) -> None:
    if value:
        print(__version__)
        raise typer.Exit(0)


UidOption = Annotated[
    str | None,
    typer.Option(help="Specify a user or uid to drop privileges to"),
]
GidOption = Annotated[
    str | None,
    typer.Option(help="Specify a group or gid to drop privileges to"),
]
AllowRootOption = Annotated[
    bool,
    typer.Option(
        "--allow-run-as-root",
        help="Accepted for compatibility; privilege dropping is controlled by --uid and --gid.",
    ),
]


@app.callback()
def cli(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Displays the current opencanary version.",
        ),
    ] = False,
) -> None:
    del version


@app.command(help="Start the opencanary process.")
def start(
    uid: UidOption = None,
    gid: GidOption = None,
    allow_run_as_root: AllowRootOption = False,
) -> None:
    del allow_run_as_root
    raise typer.Exit(_start(uid, gid, nodaemon=False))


@app.command(help="Run opencanary in the foreground.")
def dev(
    uid: UidOption = None,
    gid: GidOption = None,
    allow_run_as_root: AllowRootOption = False,
) -> None:
    del allow_run_as_root
    raise typer.Exit(_start(uid, gid, nodaemon=True))


@app.command(help="Stop the opencanary process.")
def stop() -> None:
    raise typer.Exit(_stop())


@app.command(help="Restart the opencanary process.")
def restart(
    uid: UidOption = None,
    gid: GidOption = None,
    allow_run_as_root: AllowRootOption = False,
) -> None:
    del allow_run_as_root
    raise typer.Exit(_restart(uid, gid))


@app.command(help="Run opencanary in foreground with only usermodules enabled.")
def usermodule() -> None:
    raise typer.Exit(_usermodule())


@app.command(help=f"Create a default config file at {CONFIG_PATH}.")
def copyconfig() -> None:
    raise typer.Exit(_copyconfig())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
