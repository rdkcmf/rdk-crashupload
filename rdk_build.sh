#!/bin/bash
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

#######################################
#
# Build Framework standard script for
#
# Flashplayer component

# use -e to fail on any shell issue
# -e is the requirement from Build Framework
set -ex

# default PATHs - use `man readlink` for more info
# the path to combined build
export RDK_PROJECT_ROOT_PATH="${RDK_PROJECT_ROOT_PATH-$(readlink -m ..)}"
export COMBINED_ROOT="$RDK_PROJECT_ROOT_PATH"

# path to build script (this script)
export RDK_SCRIPTS_PATH="${RDK_SCRIPTS_PATH-$(readlink -m "$0" | xargs dirname)}"

# path to components sources and target
export RDK_SOURCE_PATH="${RDK_SOURCE_PATH-$RDK_SCRIPTS_PATH/..}"
export RDK_TARGET_PATH="${RDK_TARGET_PATH-$RDK_SOURCE_PATH}"

# fsroot and toolchain (valid for all devices)
export RDK_FSROOT_PATH="${RDK_FSROOT_PATH-$(readlink -m "$RDK_PROJECT_ROOT_PATH/sdk/fsroot/ramdisk")}"
#export RDK_TOOLCHAIN_PATH=${RDK_TOOLCHAIN_PATH-`readlink -m $RDK_PROJECT_ROOT_PATH/sdk/toolchain/staging_dir`}

# default component name
export RDK_COMPONENT_NAME="${RDK_COMPONENT_NAME-$(basename "$RDK_SOURCE_PATH")}"

#DEBUG=0
#COMBINED=1
#UPLOAD=0
#REBUILD=0
#JOBS_NUM=0 # 0 means detect automatically
#PROJECT_CONFIG=()

# parse arguments
INITIAL_ARGS=$@

function usage()
{
    set +x
    echo "Usage: $(basename "$0") [-h|--help] [-v|--verbose] [action]"
    echo "    -h    --help                  : this help"
    echo "    -v    --verbose               : verbose output"
    echo
    echo "Supported actions:"
    echo "      configure, clean, build (DEFAULT), rebuild, install"
}

# options may be followed by one colon to indicate they have a required argument
if ! GETOPT=$(getopt -n "build.sh" -o hv:h -l help,verbose -- "$@")
then
    usage
    exit 1
fi

eval set -- "$GETOPT"

while true; do
  case "$1" in
    -h | --help ) usage; exit 0 ;;
    -v | --verbose ) set -x ;;
    -- ) shift; break;;
    * ) break;;
  esac
  shift
done

ARGS=$@


# component-specific vars
#export TOOLCHAIN_DIR=$COMBINED_ROOT/sdk/toolchain/staging_dir
src_file=uploadDumps.sh
src_file_hdd=uploadDumpsHDD.sh
install_dir=$RDK_FSROOT_PATH/lib/rdk
src_generic=$RDK_SOURCE_PATH/generic/$src_file
src_generic_hdd=$RDK_SOURCE_PATH/generic/$src_file_hdd
src_devspec=$RDK_SOURCE_PATH/devspec/$src_file
dst=$install_dir/$src_file

# functional modules

function configure()
{
    true
}

function clean()
{
    true
}

function build()
{
    :
    #pushd $RDK_SOURCE_PATH/generic/upload-dumps-2
    #./unit_test.sh
    #popd
}

function rebuild()
{
    build
}

function install()
{
#    # Avoid unnecessary copying and stripping.
#    if [ -f $dst ]; then
#        echo "$src_file is present in $install_dir already. Nothing to install."
#        return
#    fi

    # Install the library to fsroot.
    echo "Installing $src_file to $install_dir"
    mkdir -p "$install_dir"

    # only xg1 devices have HDD.
    HDD_DEVICES="xg1"

    for device in $HDD_DEVICES
    do
        if [ "$device" = "$RDK_PLATFORM_DEVICE" ] ; then
            HAS_HDD="true"
        fi
    done

    if [ "$HAS_HDD" = "true" -a -f "$src_generic_hdd" ]; then
       echo "Copying uploadDumpsHDD file $src_generic_hdd"
       cp "$src_generic_hdd" "$dst"
    elif [ -f "$src_generic" ]; then
        echo "Copy generic $src_file."
        cp "$src_generic" "$dst"
    fi

    if [! -f "$src_generic" -o ! -f "$src_generic_hdd" ]; then
        echo "Missing $src_file...!"
        exit 1
    fi
}

# run the logic

HIT=false

for i in $ARGS; do
    case $i in
        configure)  HIT=true; configure ;;
        clean)      HIT=true; clean ;;
        build)      HIT=true; build ;;
        rebuild)    HIT=true; rebuild ;;
        install)    HIT=true; install ;;
        *)
            #skip unknown
        ;;
    esac
done

# if not HIT do install by default
if ! $HIT; then
  install
fi
