#!/bin/sh
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

if [ -f /lib/rdk/t2Shared_api.sh ]; then
	source /lib/rdk/t2Shared_api.sh
        IS_T2_ENABLED="TRUE"
fi

# functions declaration --------------------------------------------------------

exit_impl()
{
    exit "$1"
}

log_info()
{
    local message="[PID:$$ $(date -u +%Y/%m/%d-%H:%M)]: $1"

    if [ "${ENABLE_UNIT_TESTS}" = "true" ]; then
        file="$(dirname "$0")/log.txt"
    else
        file="${UD_CORE_LOG}"
    fi

    echo "$message" >> "$file"
}

log_error()
{
    local message="[PID:$$ $(date -u +%Y/%m/%d-%H:%M)]: ***ERROR: $1"

    if [ "${ENABLE_UNIT_TESTS}" = "true" ]; then
        file="$(dirname "$0")/log.txt"
    else
        file="${UD_CORE_LOG}"
    fi

    echo "$message" >> "$file"
}

log_fatal()
{
    log_error "$1"
    exit_impl 255
}

log_std_out()
{
    while read line; do
        log_info "${line}"
    done
}

at_exit()
{
    local exit_code=$?
    unlock
    if [ ${exit_code} -ne 0 ]; then
        log_error "Upload failed."
    fi
    exit ${exit_code}
}

unlock()
{
    rmdir "${UD_LOCK_DIR}" || log_error "Cannot unlock! Error deleting ${UD_LOCK_DIR}."
    trap - INT TERM EXIT
}

try_lock()
{
    if [ -d "${UD_LOCK_DIR}" ]; then
        log_info "Script is already working, exit."
        exit_impl 0
    fi
    mkdir "${UD_LOCK_DIR}"
    trap "at_exit" INT TERM EXIT
}

get_last_modified_time_of_file()
{
    if [ -f "$1" ] ; then
        stat -c '%y' "$1" | cut -d '.' -f1 | sed -e 's/[ :]/-/g'
    fi
}

is_file_size_changing()
{
    local initial_size=$(stat -c%s "$1")
    sleep 3
    local size_after_a_while=$(stat -c%s "$1")

    if [ "${initial_size}" -ne "${size_after_a_while}" ]; then
        return 0
    else
        return 255
    fi
}

# UD object functions declaration

ud_initialize()
{
    # Script input parameter handling
    if [ $# -lt 1 ]; then
        log_fatal "Missing running mode operand...
                   Usage: $0 MODE
                   Mandatory argument -m|--mini| indicates
                   script working mode"
    fi

    for i in "$@"
    do
        case "$i" in
        -m | --mini )
            UD_MODE="MINIDUMP"
            ;;
        esac
    done
    if [ -z "$UD_MODE" ]; then
        UD_MODE="MINIDUMP"
    fi

    # imported variable list
    # HAS_HDD
    # BUILD_TYPE
    # BOX_TYPE
    # UD_MODEL_NUM # <-- taken from version.txt

    # sanitize vars
    UD_HAS_HDD=${HAS_HDD-"false"}
    UD_VERSION_FILE=${VERSION_FILE-"/version.txt"}
    UD_BOX_TYPE=${BOX_TYPE-"UNKNOWN"}
    UD_BUILD_TYPE=${BUILD_TYPE-"prod"}

    UD_LOG_PATH=${LOG_PATH-"/opt/logs"}
    UD_RECEIVER_FULLPATH=${RECEIVER_FULLPATH-"/mnt/nfs/env/Receiver"}
    UD_CORE_LOG=${CORE_LOG-"$UD_LOG_PATH/core_log.txt"}
    UD_UPLOAD_USER=${UPLOAD_USER-"ccpstbscp"}
    UD_UPLOAD_IDENTITY_FILE=${UPLOAD_IDENTITY_FILE-"/.ssh/id_dropbear"}

    UD_LOCK_DIR="/tmp/.upload_dumps.lock"
    UD_CRASH_PORTAL_MINIDUMPS_PATH="/opt/crashportal_uploads/minidumps/"
    UD_MINIDUMPS_WORKING_PATH="/opt/minidumps"

    UD_WORKING_PATH=${UD_MINIDUMPS_WORKING_PATH}

    if [ "${UD_BUILD_TYPE}" = "prod" ]; then
        UD_CPL_HOST=$(tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalPRODUrl 2>&1)
        if [ -z "$UD_CPL_HOST" ]; then
            UD_CPL_HOST="crashportal.ccp.xcal.tv"
        fi        
    elif [ "${UD_BUILD_TYPE}" = "vbn" ]; then
        UD_CPL_HOST=$(tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalVBNUrl 2>&1)
        if [ -z "$UD_CPL_HOST" ]; then
            UD_CPL_HOST="vbn.crashportal.ccp.xcal.tv"
        fi
    elif [ "${UD_BUILD_TYPE}" = "dev" ]; then
        UD_CPL_HOST=$(tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalDEVUrl 2>&1)
        if [ -z "$UD_CPL_HOST" ]; then
            UD_CPL_HOST="crashportal.dt.ccp.cable.comcast.com"
        fi
    else
        # LAB2 Crash Portal
        UD_CPL_HOST="162.150.27.194"
    fi
}

ud_compose_filename()
{
    local fullName="${UD_SHA1}_mac${UD_MAC}_dat${UD_TIMESTAMP}_box${UD_BOX_TYPE}_mod${UD_MODEL_NUM}_$(basename ${UD_DUMP_FILE_PATH})"
    log_info "Composed filename is ${fullName}"

    echo "${fullName}"
}

ud_get_file_timestamp()
{
    local TIMESTAMP_DEFAULT_VALUE="2000-01-01-00-00-00"
    local timestamp=$(get_last_modified_time_of_file "$1")
    if [ ! -n "${timestamp}" ] ; then
        log_error "Timestamp of $1 is empty. Setting default value."
        timestamp=${TIMESTAMP_DEFAULT_VALUE}
    fi
    echo ${timestamp}
}

ud_check_log_file()
{
    if [ -z "${UD_LOG_PATH}" ]; then
        log_fatal "variable UD_LOG_PATH is empty, exiting"
    fi

    mkdir -p "${UD_LOG_PATH}"
    if [ ! -f "${UD_CORE_LOG}" ]; then
        touch "${UD_CORE_LOG}"
        ec=$?
        if [ $ec -ne 0 ]; then
            # we can't log, so only "echo" the error
            echo "unable to write to ${UD_CORE_LOG}"
            exit_impl 255
        fi
        chmod a+w "${UD_CORE_LOG}"
    fi
}

ud_set_mac_address()
{
    local MAC_DEFAULT_VALUE="000000000000"
    local SLEEP_INTERVAL=30
    if [ "${ENABLE_UNIT_TESTS}" = "true" ]; then
        SLEEP_INTERVAL=1
    fi

    for i in 1 2 3 4 5; do
        # different STB could have their own method of getting MAC address
        UD_MAC=$(getMacAddressOnly | tr a-f A-F | sed -e "s/://g")

        if [ "${#UD_MAC}" -eq 12 ] ; then
            break;
        fi
        sleep ${SLEEP_INTERVAL}
    done

    if [ ! -n "${UD_MAC}" ] ; then
        log_error "Cannot get MAC. Setting to default value."
        log_error "Output of ifconfig:"
        ifconfig -a 2>&1 | log_std_out
        UD_MAC=${MAC_DEFAULT_VALUE}
        return
    else
        UD_MAC=$(echo "${UD_MAC}" | tr a-f A-F | sed -e "s/://g")
    fi

    # if MAC value has spaces assign default value
    if printf %012X "0x${UD_MAC}" >/dev/null 2>/dev/null; then
        UD_MAC=$(printf %012X "0x${UD_MAC}")
    else
        UD_MAC=${MAC_DEFAULT_VALUE}
    fi
}

ud_set_sha1_sum()
{
    local SHA1_DEFAULT_VALUE="0000000000000000000000000000000000000000"

    UD_SHA1=$(sha1sum "${UD_RECEIVER_FULLPATH}" | cut -f1 -d" ")
    if [ ! -n "${UD_SHA1}" ] ; then
        log_error "SHA1 is empty. Setting default value."
        UD_SHA1=${SHA1_DEFAULT_VALUE}
    fi
}

ud_set_model_num()
{
    UD_MODEL_NUM="$(head "/${UD_VERSION_FILE}" | grep imagename: | sed -re 's@imagename:([^_]*).*@\1@g')"
    log_info "UD_MODEL_NUM is now ${UD_MODEL_NUM}"
}

ud_backup_dump_file_if_needed()
{
    # copy $1 when backup enabled and UD_MODE==COREDUMP
    # return 0 if copy succeeded
    if [ "${UD_MODE}" = "MINIDUMP" ]; then
        log_info "Skip backup minidump $1"
        return 1
    fi

    if [ ! -d "${COREDUMPS_BACKUP_DIR}" ]; then
        log_error "No backup dir present."
        return 1
    fi

    cp "$1" "${COREDUMPS_BACKUP_DIR}/core.prog${1##*core.prog}"
    ec=$?
    if [ $ec -ne 0 ]; then
        log_error "Code: $ec. Could not copy $1 to backup dir."
        return 1
    fi

    return 0
}

ud_create_dump_archive()
{
    # copy files to archive into the working dir and archive them
    local file_list="${UD_DUMP_FILE_PATH} ${UD_VERSION_FILE} ${UD_CORE_LOG}"

    if [ "${UD_BUILD_TYPE}" != "prod" ]; then
        # if the build type is not PROD we should add all
        # logs into resulting tarball
        if [ -f "${UD_LOG_PATH}/ocapri_log.txt" ]; then
            file_list=${file_list}" ${UD_LOG_PATH}/ocapri_log.txt"
        fi
        if [ -f "${UD_LOG_PATH}/messages.txt" ]; then
            file_list=${file_list}" ${UD_LOG_PATH}/messages.txt"
        fi
        if [ -f "${UD_LOG_PATH}/app_status_backup.log" ]; then
            file_list=${file_list}" ${UD_LOG_PATH}/app_status_backup.log"
        fi
    fi

    if [ -f "${UD_LOG_PATH}/receiver.log" ]; then
        file_list=${file_list}" ${UD_LOG_PATH}/receiver.log"
    fi

    UD_DUMP_ARCHIVE_FILE_PATH=$(ud_compose_filename)".tgz"

    log_info "Creating tarball with ${file_list}..."
    nice -n 19 tar -zcvf ${UD_DUMP_ARCHIVE_FILE_PATH} \
                         ${file_list} 2>&1 | log_std_out

    ec=$?
    if [ ${ec} -eq 0 ]; then
        log_info "Compression succeeded."
    else
        log_error "Compression failed with error code ${ec}."
    fi
}

ud_upload_dump_archive()
{
    local dirnum=$((RANDOM%100))
    if [ "${dirnum}" -ge "0" -a "${dirnum}" -le "9" ]; then
        dirnum="0${dirnum}"
    fi

    local remote_path="${UD_CRASH_PORTAL_MINIDUMPS_PATH}/${dirnum}/"

    log_info "Upload string: scp -v -i ${UD_UPLOAD_IDENTITY_FILE} \
        ./${UD_DUMP_ARCHIVE_FILE_PATH} \
        ${UD_UPLOAD_USER}@${UD_CPL_HOST}:${remote_path}"
    nice -n 19 scp -v -i "${UD_UPLOAD_IDENTITY_FILE}" \
        "./${UD_DUMP_ARCHIVE_FILE_PATH}" \
        "${UD_UPLOAD_USER}@${UD_CPL_HOST}:${remote_path}" 2>&1 | log_std_out

    ec=$?
    if [ ${ec} -eq 0 ]; then
        log_info "Success uploading file: ${UD_DUMP_ARCHIVE_FILE_PATH} \
                  to ${UD_CPL_HOST}:${remote_path}." 
        if [ "$IS_T2_ENABLED" == "TRUE" ]; then
		t2CountNotify "SYS_INFO_CrashPortalUpload_success"
        fi        
    else
        log_error "Uploading to ${UD_CPL_HOST} failed with error code ${ec}."
	if [ "$IS_T2_ENABLED" == "TRUE" ]; then
                t2CountNotify "SYST_ERR_CrashPortalUpload_failed"
        fi
    fi
}

ud_cleanup()
{
    # remove dumps and tarballs
    rm -f "${UD_DUMP_ARCHIVE_FILE_PATH}"
    rm -f "${UD_DUMP_FILE_PATH}"
}

ud_set_dump_file ()
{
   local file_path=$1
   # TODO(iivlev): check the file_path type

   # check if file is ready to be processed:
   if is_file_size_changing "${file_path}"; then
      return 255
   fi
   UD_DUMP_FILE_PATH=${file_path}
   UD_TIMESTAMP=$(ud_get_file_timestamp "${UD_DUMP_FILE_PATH}")
   return 0
}

ud_upload_dumps()
{
    local working_dir=${UD_WORKING_PATH}

    pushd "${working_dir}"

    # remove all archives in a working_dir assuming that they are incomplete
    find "${working_dir}" -name "*.tgz" -type f -exec rm -f {} \;

    # for all files in ${working dir}
    find "${working_dir}" -type f -print | \
        while read file_path; do
            if ! ud_set_dump_file; then
                log_info "Skip ${file_path}"
                continue
            fi

            ud_backup_dump_file_if_needed "${UD_DUMP_FILE_PATH}" || true
            ud_create_dump_archive
            ud_upload_dump_archive
            ud_cleanup
        done

    popd
}

# end of functions declaration -------------------------------------------------

if [ "${ENABLE_UNIT_TESTS}" != "true" ]; then
    set -e
    set -o pipefail

    # import
    . /etc/common.properties
    . /etc/device.properties
    . /etc/include.properties
    . "${RDK_PATH}"/utils.sh
    if [ -e "${RDK_PATH}"/commonUtils.sh ]; then
        . "${RDK_PATH}"/commonUtils.sh
    fi

    ud_initialize "$@"

    ud_check_log_file

    try_lock

    ud_set_mac_address
    ud_set_sha1_sum
    ud_set_model_num
    ud_upload_dumps

    unlock
fi
