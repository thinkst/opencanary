import os
import shutil
import signal
import sys
from importlib.resources import as_file, files
from pathlib import Path
from typing import Annotated

import typer
from twisted.python import usage
from twisted.scripts._twistd_unix import ServerOptions, UnixApplicationRunner

from opencanary import __version__

PIDFILE = Path("/var/run/opencanary.pid")
CONFIG_DIR = Path("/etc/opencanaryd")
CONFIG_NAME = "opencanary.conf"
app = typer.Typer(add_completion=False, invoke_without_command=True)


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
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 1

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
    _warn_drop_privileges(uid, gid)
    with _resource_path("opencanary.tac") as tac_path:
        options = ["--python", str(tac_path), "--pidfile", str(PIDFILE)]
        if nodaemon:
            options.insert(0, "--nodaemon")
        else:
            options.extend(["--syslog", "--prefix=opencanary"])
        options.extend(_twistd_flags(uid, gid))
        return _run_twistd(options)


def _copyconfig() -> int:
    destination = CONFIG_DIR / CONFIG_NAME
    if destination.exists():
        print(
            "A config file already exists at /etc/opencanaryd/opencanary.conf, please move it first"
        )
        return 1

    if os.geteuid() != 0:
        print(
            "Writing /etc/opencanaryd/opencanary.conf requires root. Run `sudo opencanary --copyconfig`.",
            file=sys.stderr,
        )
        return 1

    with _resource_path("data/settings.json") as default_config:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy(default_config, destination)

    print("[*] A sample config file is ready /etc/opencanaryd/opencanary.conf\n")
    print('[*] Edit your configuration, then launch with "opencanary --start"')
    return 0


def _usermodule() -> int:
    with _resource_path("data/settings-usermodule.json") as usermod_config:
        current_config = Path(CONFIG_NAME)
        if current_config.exists() and current_config.read_bytes() != Path(
            usermod_config
        ).read_bytes():
            print("Backing up old config to ./opencanary.conf.old")
            shutil.copy(current_config, current_config.with_suffix(".conf.old"))

        shutil.copy(usermod_config, current_config)

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
            f"Stopping process {pid} requires sufficient permissions. Run `sudo opencanary --stop` if needed.",
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


@app.callback()
def cli(
    start: Annotated[
        bool,
        typer.Option(help="Starts the opencanary process"),
    ] = False,
    dev: Annotated[
        bool,
        typer.Option(help="Run the opencanary process in the foreground"),
    ] = False,
    stop: Annotated[
        bool,
        typer.Option(help="Stops the opencanary process"),
    ] = False,
    restart: Annotated[
        bool,
        typer.Option(help="Restarts the opencanary process"),
    ] = False,
    usermodule: Annotated[
        bool,
        typer.Option(help="Run opencanary in foreground with only usermodules enabled"),
    ] = False,
    copyconfig: Annotated[
        bool,
        typer.Option(
            help="Creates a default config file at /etc/opencanaryd/opencanary.conf"
        ),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Displays the current opencanary version.",
        ),
    ] = False,
    uid: Annotated[
        str | None,
        typer.Option(help="Specify a user or uid to drop privileges to"),
    ] = None,
    gid: Annotated[
        str | None,
        typer.Option(help="Specify a group or gid to drop privileges to"),
    ] = None,
    allow_run_as_root: Annotated[
        bool,
        typer.Option(
            "--allow-run-as-root",
            help="Accepted for compatibility; privilege dropping is controlled by --uid and --gid.",
        ),
    ] = False,
) -> None:
    del version
    del allow_run_as_root

    selected_actions = [
        start,
        dev,
        stop,
        restart,
        usermodule,
        copyconfig,
    ]
    action_count = sum(selected_actions)
    if action_count != 1:
        print(
            "Exactly one action flag is required: --start, --dev, --stop, --restart, --usermodule, or --copyconfig.",
            file=sys.stderr,
        )
        raise typer.Exit(1)

    if copyconfig:
        raise typer.Exit(_copyconfig())
    if usermodule:
        raise typer.Exit(_usermodule())
    if stop:
        raise typer.Exit(_stop())
    if restart:
        raise typer.Exit(_restart(uid, gid))
    if start:
        raise typer.Exit(_start(uid, gid, nodaemon=False))

    raise typer.Exit(_start(uid, gid, nodaemon=True))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
