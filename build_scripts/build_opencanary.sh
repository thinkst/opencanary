#!/bin/bash -e
# Build opencanary package and create virtualenv where it can be run.

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


# Bash fxn to move files/dirs out of the way
mv_to_old() {
    local FILE_TO_MOVE="$1"
    local OLD_COPY="$1.old"
    [[ -a $OLD_COPY ]] && mv_to_old $OLD_COPY   # Recursively move old copies out the way
    echo "Moving '$FILE_TO_MOVE' out of the way to '$OLD_COPY'"
    mv "$FILE_TO_MOVE" "$OLD_COPY"
}

# Create python virtual env
create_venv() {
    echo "Creating new virtualenv in '$VENV_DIR'..."
    $VENV_CREATION_CMD "$VENV_PATH" >> "$BUILD_LOG"
}


echo -e "Build log will be written to '$BUILD_LOG'..."
pushd "$OPENCANARY_DIR" >> "$BUILD_LOG"


if [[ $SYSTEM_INFO =~ 'Darwin' ]]; then
    echo 'macOS detected...'

    if ! command -v brew &>/dev/null; then
        echo 'ERROR: homebrew not found. Try visiting https://brew.sh/'
        exit 1
    fi

    set +e
    OPENSSL_PATH=$(brew --prefix "$HOMEBREW_OPENSSL_FORMULA" 2>/dev/null)

    if [ $? -ne 0 ] ; then
        echo "ERROR: $HOMEBREW_OPENSSL_FORMULA not found. Try 'brew install $HOMEBREW_OPENSSL_FORMULA'."
        exit 1
    fi

    set -e

    if [[ $SYSTEM_INFO =~ 'X86' ]]; then
        echo 'x86 detected...'
        export ARCHFLAGS="-arch x86_64"
    elif [[ $SYSTEM_INFO =~ 'ARM64' ]]; then
        echo 'm1 detected...'
        export ARCHFLAGS="-arch arm64"
    else
        echo "ERROR: Architecture not identifiable from system info, exiting."
        echo -e "'uname -a' output was: $SYSTEM_INFO"
        exit 1
    fi

    export LDFLAGS="-L$OPENSSL_PATH/lib"
    export CPPFLAGS="-I$OPENSSL_PATH/include"

    echo -e "Found $HOMEBREW_OPENSSL_FORMULA at '$OPENSSL_PATH'"
    echo -e "    LDFLAGS set to '$LDFLAGS'"
    echo -e "    CPPFLAGS set to '$CPPFLAGS'"
    echo -e "    ARCHFLAGS set to '$ARCHFLAGS'"
else
    echo "Unknown system. You may need to set LDFLAGS, CPPFLAGS, and ARCHFLAGS to compile 'cryptography'."
fi


# Backup current checkout and pull a fresh one from github if requested
if [ "${OPENCANARY_BUILD_FULL_CLEAN+set}" = set ]; then
    echo "OPENCANARY_BUILD_FULL_CLEAN requested; backing up repo and rebuilding from scratch..."
    pushd ..
    [[ -a opencanary ]] && mv_to_old opencanary
    git clone "$OPENCANARY_GIT_REPO"
    popd
else
    echo "Using current repo at '$OPENCANARY_DIR'"
    echo "    (Set OPENCANARY_BUILD_FULL_CLEAN=true to start from a fresh git checkout)"
fi


# Backup current virtual env and make a new one if requested
if [[ -d $VENV_PATH ]]; then
    if [[ "${OPENCANARY_BUILD_FRESH_VENV+set}" = set ]]; then
        mv_to_old "$VENV_PATH"
        create_venv
    else
        echo "Using current virtualenv in '$VENV_PATH'"
        echo "    (Set OPENCANARY_BUILD_FRESH_VENV=true to rebuild a new virtualenv)"
    fi
else
    create_venv
fi


echo "Activating virtual env..."
. "$VENV_PATH/bin/activate"

echo "Installing cryptography package..."
pip3 install cryptography >> "$BUILD_LOG"

echo Building...
python3 setup.py sdist >> "$BUILD_LOG" 2>&1
BUILT_PKG=$(ls dist/opencanary*.tar.gz)

echo "Installing built package '$BUILT_PKG'..."
pip install dist/opencanary-0.7.1.tar.gz >> "$BUILD_LOG"

echo -e "\nInstall complete.\nIMPORTANT: virtualenv is NOT active. To activate now and in the future:"
echo -e "\n    . '$OPENCANARY_DIR/env/bin/activate'\n\n"
popd >> "$BUILD_LOG"
