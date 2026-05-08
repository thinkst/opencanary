# OpenCanary Modernization Plan

This file tracks the modernization work for this repository.

Rules for execution:
- Keep tasks small enough for straightforward review.
- Complete one checkbox-sized task per change unless two items are tightly coupled.
- Update this file in the same change that completes the task.
- If scope changes, add new unchecked items rather than silently expanding an existing one.

## Phase 0: Guardrails

- [ ] Confirm the target modernization order and keep this file as the source of truth.
- [ ] Add a short contributor note to the README describing how modernization tasks are tracked in `PLAN.md`.

## Phase 1: Packaging And CLI

- [x] Replace `tool.setuptools.script-files` with `project.scripts` entry points in `pyproject.toml`.
- [x] Move `opencanary --version` logic from the Bash wrapper into Python.
- [x] Move `--copyconfig` logic from the Bash wrapper into Python.
- [x] Move `--start` and `--dev` argument parsing into a Python CLI module.
- [x] Move `--stop` and `--restart` PID management into Python or remove those commands if they are no longer justified.
- [x] Remove `python3 -c` calls from the old `bin/opencanary` wrapper.
- [x] Remove the custom `sudo()` shell function from the old `bin/opencanary` wrapper.
- [x] Replace remaining `pkg_resources.resource_filename` usage with `importlib.resources`.
- [x] Update source-install documentation to stop using `setup.py sdist`.
- [x] Align Python version classifiers with `requires-python`.

## Phase 2: Config Loading And Validation

- [x] Remove config loading side effects from module import in `opencanary/config.py`.
- [x] Expose a pure config loading function that returns a config object without exiting the process.
- [x] Expose a pure config validation function that returns structured errors.
- [x] Move process exit behavior for invalid config into the CLI startup path.
- [x] Add unit tests for config file search order.
- [x] Add unit tests for environment-variable expansion in config values.
- [x] Add unit tests for port collision validation.
- [x] Add unit tests for key field validation such as `device.name`, `device.desc`, and `ssh.version`.
- [x] Keep JSON config for now and treat a typed schema model as a follow-up phase after the test and linting work lands.

## Phase 3: Linting, Formatting, And Type Safety

- [ ] Upgrade pre-commit hook versions.
- [ ] Replace the Black and Flake8 combination with Ruff, or document why not.
- [ ] Add a repository-local lint configuration in `pyproject.toml`.
- [ ] Enable at least one import/order and one bug-risk rule set in linting.
- [ ] Replace deprecated `logger.warn` usage with `logger.warning`.
- [ ] Remove mutable default arguments where present.
- [ ] Replace broad bare `except` blocks where practical with narrower exceptions.
- [ ] Add a basic type-checking configuration for `mypy` or `pyright`.
- [ ] Type annotate config and logging modules first.

## Phase 4: Test Modernization

- [ ] Split the current monolithic integration tests into smaller pytest modules by protocol.
- [ ] Add pytest fixtures for temporary config files and log capture.
- [ ] Stop relying on `/var/tmp/opencanary.log` in the default test path.
- [ ] Start services under test from fixtures instead of assuming OpenCanary is already installed and running.
- [ ] Convert `unittest.TestCase` tests to plain pytest style where practical.
- [ ] Mark slow end-to-end protocol tests explicitly.
- [ ] Add a minimal fast test job that can run on every PR.
- [ ] Keep one smoke end-to-end workflow that exercises the packaged daemon.

## Phase 5: CI And Release Pipeline

- [ ] Run CI on `pull_request` as well as `push`.
- [ ] Standardize Python setup across workflows.
- [ ] Cache dependencies consistently across lint and test jobs.
- [ ] Split lint, fast tests, and slow integration tests into separate jobs.
- [ ] Review the OS and Python matrix for cost versus value and trim if needed.
- [ ] Make release validation use the packaged CLI entry point rather than shell glue.
- [ ] Review whether publish and Docker workflows should trigger from tags, releases, or both.

## Phase 6: Docker And Runtime Packaging

- [ ] Rework `Dockerfile.latest` so dependency installation is driven by package metadata and lockfiles explicitly.
- [ ] Remove editor and admin packages such as `vim` and `sudo` from the runtime image.
- [ ] Add a non-root runtime user in the container image.
- [ ] Separate build and runtime stages if it reduces image size and attack surface.
- [ ] Confirm the image still supports required privilege-dropping behavior.
- [ ] Document the supported Docker runtime model in the README.

## Phase 7: Logging And Runtime Internals

- [ ] Refactor logger setup to return errors cleanly instead of printing and exiting deep in library code.
- [ ] Normalize timestamp handling in log records.
- [ ] Add tests around ignore-list behavior in logging.
- [ ] Review retry behavior in `SocketJSONHandler` and make it easier to test.
- [ ] Decide whether `simplejson` is still required or whether the standard library `json` module is sufficient.

## Phase 8: Module Architecture

- [ ] Remove or reduce the global monkey-patching of Twisted `Protocol` in `opencanary/modules/__init__.py`.
- [ ] Make service wiring more explicit so module behavior is easier to test in isolation.
- [ ] Define a clearer contract for module lifecycle and logging hooks.
- [ ] Add focused tests for one TCP module and one UDP module using the new contract.
- [ ] Reassess whether a larger Twisted architecture refactor is justified after the earlier phases land.

## Phase 9: Documentation Cleanup

- [ ] Refresh installation instructions to prefer the current supported path.
- [ ] Document the Python version support policy in one place.
- [ ] Add a short developer setup section for linting, tests, and local runs.
- [ ] Document which tests are fast unit tests versus slower integration tests.
- [ ] Remove stale or duplicated instructions once the new CLI path is in place.

## Working Notes

- Start with Phase 1, Phase 2, and Phase 3. They unblock the rest.
- Prefer changes that reduce import-time side effects before deeper test refactors.
- Treat architecture rewrites as follow-up work, not the first milestone.
- Keep JSON config loading for now; revisit a typed schema after the Phase 3 and Phase 4 groundwork is in place.
