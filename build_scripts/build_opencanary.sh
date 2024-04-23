#!/bin/bash -e
# Build opencanary package from git repo and create virtualenv where it can be run.
# Tested on macOS but should work elsewhere as long as the compile flags are configured.
#
# Environment variable options:
#    OPENCANARY_BUILD_FULL_CLEAN=True - do a new git checkout
#    OPENCANARY_BUILD_FRESH_VENV=True - recreate the venv

# Configurable variables
OPENCANARY_GIT_REPO="https://github.com/thinkst/opencanary.git"
HOMEBREW_OPENSSL_FORMULA="openssl@1.1"
VENV_DIR=env
VENV_CREATION_CMD='python3 -m venv'

# System info
SYSTEM_INFO=`uname -a`
BUILD_SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0";)";)
OPENCANARY_DIR="$(readlink -f -- "$BUILD_SCRIPT_DIR/../";)"
BUILD_LOG="$BUILD_SCRIPT_DIR/build.log"
VENV_PATH="$OPENCANARY_DIR/$VENV_DIR"


# Echo a string to both STDOUT and the build log
echo_log() {
    echo -e "$1"
    echo >> $BUILD_LOG
    echo -e "$1" >> "$BUILD_LOG"
    echo >> $BUILD_LOG
}

# Bash fxn to move files/dirs out of the way
mv_to_old() {
    local FILE_TO_MOVE="$1"
    local OLD_COPY="$1.old"
    [[ -a $OLD_COPY ]] && mv_to_old $OLD_COPY   # Recursively move old copies out the way
    echo_log "Moving '$FILE_TO_MOVE' out of the way to '$OLD_COPY'"
    mv -v "$FILE_TO_MOVE" "$OLD_COPY" >> "$BUILD_LOG"
}

# Create python virtual env
create_venv() {
    echo_log "Creating new virtualenv in '$VENV_DIR'..."
    $VENV_CREATION_CMD "$VENV_PATH" >> "$BUILD_LOG"
}


echo -e "Build log will be written to '$BUILD_LOG'..."
pushd "$OPENCANARY_DIR" >> "$BUILD_LOG"


if [[ $SYSTEM_INFO =~ 'Darwin' ]]; then
    echo_log 'macOS detected...'

    if ! command -v brew &>/dev/null; then
        echo_log 'ERROR: homebrew not found. Try visiting https://brew.sh/'
        exit 1
    fi

    set +e
    OPENSSL_PATH=$(brew --prefix "$HOMEBREW_OPENSSL_FORMULA" 2>/dev/null)

    if [ $? -ne 0 ] ; then
        echo_log "ERROR: $HOMEBREW_OPENSSL_FORMULA not found. Try 'brew install $HOMEBREW_OPENSSL_FORMULA'."
        exit 1
    fi

    set -e

    if [[ $SYSTEM_INFO =~ 'X86' ]]; then
        echo_log 'x86 detected...'
        export ARCHFLAGS="-arch x86_64"
    elif [[ $SYSTEM_INFO =~ 'ARM64' ]]; then
        echo_log 'm1 detected...'
        export ARCHFLAGS="-arch arm64"
    else
        echo_log "ERROR: Architecture not identifiable from system info, exiting."
        echo_log "'uname -a' output was: $SYSTEM_INFO"
        exit 1
    fi

    export LDFLAGS="-L$OPENSSL_PATH/lib"
    export CPPFLAGS="-I$OPENSSL_PATH/include"

    echo_log "Found $HOMEBREW_OPENSSL_FORMULA at '$OPENSSL_PATH'"
    echo_log "    LDFLAGS set to '$LDFLAGS'"
    echo_log "    CPPFLAGS set to '$CPPFLAGS'"
    echo_log "    ARCHFLAGS set to '$ARCHFLAGS'"
else
    echo_log "Unknown system. You may need to set LDFLAGS, CPPFLAGS, and ARCHFLAGS to compile 'cryptography'."
fi


# Backup current checkout and pull a fresh one from github if requested
if [ "${OPENCANARY_BUILD_FULL_CLEAN+set}" = set ]; then
    echo_log "OPENCANARY_BUILD_FULL_CLEAN requested; backing up repo and rebuilding from scratch..."
    pushd .. >> "$BUILD_LOG"
    [[ -a opencanary ]] && mv_to_old opencanary
    git clone "$OPENCANARY_GIT_REPO"
    popd >> "$BUILD_LOG"
else
    echo_log "Using current repo at '$OPENCANARY_DIR'"
    echo "    (Set OPENCANARY_BUILD_FULL_CLEAN=true to start from a fresh git checkout)"
fi


# Backup current virtual env and make a new one if requested
if [[ -d $VENV_PATH ]]; then
    if [[ "${OPENCANARY_BUILD_FRESH_VENV+set}" = set ]]; then
        mv_to_old "$VENV_PATH"
        create_venv
    else
        echo_log "Using current virtualenv in '$VENV_PATH'"
        echo "    (Set OPENCANARY_BUILD_FRESH_VENV=true to rebuild a new virtualenv)"
    fi
else
    create_venv
fi


echo_log "Activating virtual env in subshell..."
. "$VENV_PATH/bin/activate"

echo_log "Installing setuptools..."
pip3 install setuptools >> "$BUILD_LOG"
echo_log "Installing cryptography package..."
pip3 install cryptography >> "$BUILD_LOG"

echo_log "Building..."
python3 setup.py sdist >> "$BUILD_LOG" 2>&1
BUILT_PKG=$(ls dist/opencanary*.tar.gz)

echo_log "Installing built package '$BUILT_PKG'..."
pip install "$BUILT_PKG" >> "$BUILD_LOG" 2>&1

echo_log "Install complete.\n"

if [[ "${VIRTUAL_ENV+set}" = set ]]; then
    echo_log "IMPORTANT: virtualenv is NOT active!"
fi

echo_log "To activate the virtualenv now and in the future:"
echo_log "\n    . '$OPENCANARY_DIR/env/bin/activate'\n\n"
popd >> "$BUILD_LOG"
