#!/bin/busybox sh
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
#

#This file is from crashupload repository
#Uploads coredumps to an ftp server if there are any
LOGMAPPER_FILE="/etc/breakpad-logmapper.conf"
LOG_FILES="/tmp/minidump_log_files.txt"

if [ -f /lib/rdk/t2Shared_api.sh ]; then
    source /lib/rdk/t2Shared_api.sh
    IS_T2_ENABLED="true"
fi

if [ -f /etc/device.properties ];then
     . /etc/device.properties
else
     echo "Missing device configuration file: /etc/device.properties..!"
fi

if [ -f /etc/include.properties ];then
     . /etc/include.properties
else
     echo "Missing generic configuration file: /etc/include.properties..!"
fi

if [ -f $RDK_PATH/utils.sh ];then
     . $RDK_PATH/utils.sh
fi

if [ -f $RDK_PATH/mtlsUtils.sh ]; then
     . $RDK_PATH/mtlsUtils.sh
fi

if [ -f /lib/rdk/uploadDumpsUtils.sh ];then
     . /lib/rdk/uploadDumpsUtils.sh
fi

if [ -f /lib/rdk/uploadDumpsUtilsDevice.sh ];then
     . /lib/rdk/uploadDumpsUtilsDevice.sh
fi

if [ "$DEVICE_TYPE" != "mediaclient" ] && [ -f $RDK_PATH/commonUtils.sh ]; then
     . $RDK_PATH/commonUtils.sh
fi

if [ -f /lib/rdk/getSecureDumpStatus.sh ];then
. /lib/rdk/getSecureDumpStatus.sh
fi

# Override Options for testing non PROD builds
if [ "$DEVICE_TYPE" = "broadband" ];then
	if [ -f /nvram/coredump.properties -a $BUILD_TYPE != "prod" ];then
		. /nvram/coredump.properties
	fi
else 
	if [ -f /opt/coredump.properties -a $BUILD_TYPE != "prod" ];then
     		. /opt/coredump.properties
	fi
fi

if [ -f /etc/waninfo.sh ]; then
    . /etc/waninfo.sh
    ARM_INTERFACE=$(getWanInterfaceName)
fi

# export PATH and LD_LIBRARY_PATH for curl
export PATH=$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# causes a pipeline to produce a failure return code in case of errors
set -o pipefail

S3BUCKET="ccp-stbcrashes"
s3bucketurl="s3.amazonaws.com"
HTTP_CODE="/tmp/httpcode"
S3_FILENAME=""
CURL_UPLOAD_TIMEOUT=45
FOUR_EIGHTY_SECS=480
MAX_CORE_FILES=4

# Yocto conditionals
TLS=""
# force tls1.2 for yocto video devices and all braodband devices
if [ -f /etc/os-release ] || [ "$DEVICE_TYPE" = "broadband" ];then
    TLS="--tlsv1.2"
fi

UPLOAD_FLAG=$3
if [ -f /etc/os-release ]; then
	CORE_PATH=$CORE_PATH
fi

if [ "x$UPLOAD_FLAG" = "xsecure" ];then
        CORE_PATH="/opt/secure/corefiles"
        MINIDUMPS_PATH="/opt/secure/minidumps"
else
        CORE_PATH="/var/lib/systemd/coredump"
	MINIDUMPS_PATH="/opt/minidumps"
fi

if [ "$DEVICE_TYPE" = "broadband" ];then
        CORE_PATH="/minidumps"
        LOG_PATH="/rdklogs/logs"
        if [ ! -d $LOG_PATH ];then mkdir -p $LOG_PATH; fi
        if [ "$MULTI_CORE" = "yes" ] ;then
             COMM_INTERFACE=`get_interface_value`
        else
             COMM_INTERFACE=$INTERFACE
        fi
fi

# Log file setup
CORE_LOG="$LOG_PATH/core_log.txt"
if [[ ! -f $CORE_LOG ]]; then
    touch $CORE_LOG
    chmod a+w $CORE_LOG
fi

EnableOCSPStapling="/tmp/.EnableOCSPStapling"
EnableOCSP="/tmp/.EnableOCSPCA"

#get telemetry opt out status
getOptOutStatus()
{
    optoutStatus=0
    currentVal="false"
    #check if feature is enabled through rfc
    rfcStatus=$(tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TelemetryOptOut.Enable 2>&1 > /dev/null)
    #check the current option
    if [ -f /opt/tmtryoptout ]; then
        currentVal=$(cat /opt/tmtryoptout)
    fi
    if [ "x$rfcStatus" == "xtrue" ]; then
        if [ "x$currentVal" == "xtrue" ]; then
            optoutStatus=1
        fi
    fi
    return $optoutStatus
}

# Set the name of the log file using SHA1
setLogFile()
{
    fileName=`basename $6`
    ## Do not perform log file processing if the core name is already processed
    echo "$fileName" | grep "_mac\|_dat\|_box\|_mod" 2> /dev/null 1> /dev/null
    if [ $? -eq 0 ]; then
       echo "$fileName"
       logMessage "Core name is already processed."
    else
       echo $1"_mac"$2"_dat"$3"_box"$4"_mod"$5"_"$fileName
    fi
}

# Usage: echo "debug information" | logStdout
# This function is needed because if we would try smth like "echo 'debug' >> $LOG"
# and we wouldn't have write access rights on $LOG, 'echo' wouldn't execute
logStdout()
{
    while read line; do
        logMessage "${line}"
    done
}

# Locking functions
# If you want to leave the script earlier than EOF, you should insert
# remove_lock $LOCK_DIR_PREFIX
# before you leave.
create_lock_or_exit()
{
    path="$1"
    while true; do
        if [[ -d "${path}.lock.d" ]]; then
            logMessage "Script is already working. ${path}.lock.d. Skip launch another instance..."
            exit 0
        fi
        mkdir "${path}.lock.d" || logMessage "Error creating ${path}.lock.d"
        break;
    done
}

# creates a lock or waits until it can be created
create_lock_or_wait()
{
    path="$1"
    while true; do
        if [[ -d "${path}.lock.d" ]]; then
            logMessage "Script is already working. ${path}.lock.d. Waiting to launch another instance..."
            sleep 2
            continue
        fi
        mkdir "${path}.lock.d" || logMessage "Error creating ${path}.lock.d"
        break;
    done
}

remove_lock()
{
    path="$1"
    if [ -d "${path}.lock.d" ]; then
        rmdir "${path}.lock.d" || logMessage "Error deleting ${path}.lock.d"
    fi
}

POTOMAC_USER=ccpstbscp
# Assign the input arguments
# CRASHTS was previously taken from first argument to the script, but we decided to just generate it here.
CRASHTS=$(date +%Y-%m-%d-%H-%M-%S)
DUMP_FLAG=$2

if [ "$DUMP_FLAG" == "1" ] ; then
    DUMP_NAME="coredump"
else
    DUMP_NAME="minidump"
fi

# 3rd argument is url to POTOMAC_SVR(see runXRE), so we can't use it for wait flag
WAIT_FOR_LOCK="$4"
TIMESTAMP_DEFAULT_VALUE="2000-01-01-00-00-00"
SHA1_DEFAULT_VALUE="0000000000000000000000000000000000000000"
MAC_DEFAULT_VALUE="000000000000"
MODEL_NUM_DEFAULT_VALUE="UNKNOWN"

logMessage()
{
    message="$1"
    echo "[PID:$$ `date -u +%Y/%m/%d-%H:%M:%S`]: $message" >> $CORE_LOG
}

sanitize()
{
   toClean="$1"
   # remove all except alphanumerics and some symbols
   # don't use stmh like ${toClean//[^\/a-zA-Z0-9 :+,]/} \
   # here since it doesn't work with slash (due to old busybox version, probably)
   clean=`echo "$toClean"|sed -e 's/[^/a-zA-Z0-9 :+._,=-]//g'`
   echo "$clean"
}


MAX_UPLOAD_ATTEMPTS=3
CB_MAX_UPLOAD_ATTEMPTS=1
DIRECT_BLOCK_FILENAME="/tmp/.lastdirectfail_crashupload"
CB_BLOCK_FILENAME="/tmp/.lastcodebigfail_crashupload"

IsDirectBlocked()
{
    directret=0
    if [ -f $DIRECT_BLOCK_FILENAME ]; then
        modtime=$(($(date +%s) - $(date +%s -r $DIRECT_BLOCK_FILENAME)))
        remtime=$((($DIRECT_BLOCK_TIME/3600) - ($modtime/3600)))
        if [ "$modtime" -le "$DIRECT_BLOCK_TIME" ]; then
            logMessage "CoreUpload:Last direct failed blocking is still valid for $remtime hrs, preventing direct"
            directret=1
        else
            logMessage "CoreUpload:Last direct failed blocking has expired, removing $DIRECT_BLOCK_FILENAME, allowing direct"
            rm -f $DIRECT_BLOCK_FILENAME
        fi
    fi
    return $directret
}

IsCodeBigBlocked()
{
    codebigret=0
    if [ -f $CB_BLOCK_FILENAME ]; then
        modtime=$(($(date +%s) - $(date +%s -r $CB_BLOCK_FILENAME)))
        cbremtime=$((($CB_BLOCK_TIME/60) - ($modtime/60)))
        if [ "$modtime" -le "$CB_BLOCK_TIME" ]; then
            logMessage "CoreUpload:Last Codebig failed blocking is still valid for $cbremtime mins, preventing Codebig"
            codebigret=1
        else
            logMessage "CoreUpload:Last Codebig failed blocking has expired, removing $CB_BLOCK_FILENAME, allowing Codebig"
            rm -f $CB_BLOCK_FILENAME
        fi
    fi
    return $codebigret
}

checkParameter()
{
    local paramName=\$"$1"
    local evaluatedValue=`eval "expr \"$paramName\" "`
    if [ -z $evaluatedValue ] ; then
        case "$1" in
        sha1)
            logMessage "SHA1 is empty. Setting default value."
            eval "$1=$SHA1_DEFAULT_VALUE"
            ;;
        modNum)
            logMessage "Model num is empty. Setting default value."
            eval "$1=$MODEL_NUM_DEFAULT_VALUE"
            ;;
        *TS)
            logMessage "Timestamp is empty. Setting default value."
            eval "$1=$TIMESTAMP_DEFAULT_VALUE"
            ;;
        esac
    fi
}

checkMAC()
{
    if [ -z "$MAC" ] ; then
        logMessage "MAC address is empty. Trying to get it again, including network interfaces currently down."
        MAC=`getMacAddressOnly`
        if [ -z "$MAC" ] ; then
            logMessage "MAC address is still empty. Setting to default value."
            MAC=$MAC_DEFAULT_VALUE
            logMessage "Output of ifconfig:"
            ifconfig -a 2>&1 | logStdout
        fi
    else
        # forcibly take to UPPER case and remove colons if present
        MAC=`echo "$MAC" | tr a-f A-F | sed -e 's/://g'`
    fi
}

deleteAllButTheMostRecentFile()
{
    path=$1
    num_of_files=`find "$path" -type f | wc -l`
    if [ "$num_of_files" -gt "$MAX_CORE_FILES" ]; then
        val=$((num_of_files - MAX_CORE_FILES))
        cd $path && ls -t1 | tail -n $val >> /tmp/dumps_to_delete.txt
        logMessage "Deleting dump files: `cat /tmp/dumps_to_delete.txt`"
        while read line; do rm -rf $line; done < /tmp/dumps_to_delete.txt
        rm -rf /tmp/dumps_to_delete.txt
    fi
}

cleanup()
{
    if [ -z "$WORKING_DIR" ] || [ -z "$(ls -A $WORKING_DIR 2> /dev/null)" ]; then
        logMessage "WORKING_DIR is empty!!!"
        return
    fi

    logMessage "Cleanup ${DUMP_NAME} directory ${WORKING_DIR}"

    # find and delete files by wildcard '*_mac*_dat*' and older than 2 days
    find ${WORKING_DIR} -type f -name '*_mac*_dat*' -mtime +2 |
    while IFS= read -r file;
    do
        rm -f "$file"
        logMessage "Removed file: ${file}"
    done

    if [ ! -f /opt/.upload_on_startup ];then
        # delete version.txt
        rm -f ${WORKING_DIR}/version.txt

        # run only once on startup
        ON_STARTUP_DUMPS_CLEANED_UP="${ON_STARTUP_DUMPS_CLEANED_UP_BASE}"_"${DUMP_FLAG}"
        if [ ! -f "$ON_STARTUP_DUMPS_CLEANED_UP" ] ; then
            path="${WORKING_DIR}"

            # delete unfinished files from previous run
            deleted_files=`find "$path" -type f -name "*_mac*_dat*" -print -exec rm -f {} \;`
            logMessage "Deleting unfinished files: ${deleted_files}"

            # delete non-dump files
            # Pace X1 does not support "-not" for find, have to use "!" here:
            deleted_files=`find "$path" -type f ! -name "${DUMPS_EXTN}" -print -exec rm -f {} \;`
            logMessage "Deleting non-dump files: ${deleted_files}"

            deleteAllButTheMostRecentFile "$path"

            touch "$ON_STARTUP_DUMPS_CLEANED_UP"
       fi
    else
       if [ "$DUMP_FLAG" == "1" ];then
            rm -rf /opt/.upload_on_startup
       fi
    fi
}

finalize()
{
    cleanup
    [ -f "$crashLoopFlagFile" ] && rm -f "$crashLoopFlagFile"
    remove_lock $LOCK_DIR_PREFIX
    remove_lock "$TIMESTAMP_FILENAME"
    if [ "$DEVICE_TYPE" = "broadband" ];then
         touch /tmp/crash_reboot
    fi
}

sigkill_function()
{
    echo "Systemd Killing, Removing the script locks"
    [ -f "$crashLoopFlagFile" ] && rm -f "$crashLoopFlagFile"
    remove_lock $LOCK_DIR_PREFIX
    remove_lock "$TIMESTAMP_FILENAME"
}

sigterm_function()
{
    echo "Systemd Terminating, Removing the script locks"
    [ -f "$crashLoopFlagFile" ] && rm -f "$crashLoopFlagFile"
    remove_lock $LOCK_DIR_PREFIX
    remove_lock "$TIMESTAMP_FILENAME"
}

trap 'sigkill_function' SIGKILL
trap 'sigterm_function' SIGTERM

if [ "$DUMP_FLAG" == "1" ] ; then
    logMessage "starting coredump processing"
    WORKING_DIR="$CORE_PATH"
    DUMPS_EXTN=*core.prog*.gz
    TARBALLS=*.core.tgz
    #to limit this to only one instance at any time..
    LOCK_DIR_PREFIX="/tmp/.uploadCoredumps"
    CRASH_PORTAL_PATH="/opt/crashportal_uploads/coredumps/"
else
    logMessage "starting minidump processing"
    if [ "$DEVICE_TYPE" = "broadband" ];then
        WORKING_DIR="/minidumps"
    else
        WORKING_DIR="$MINIDUMPS_PATH"
    fi
    DUMPS_EXTN=*.dmp
    TARBALLS=*.dmp.tgz
    CRASH_PORTAL_PATH="/opt/crashportal_uploads/minidumps/"
    #to limit this to only one instance at any time..
    LOCK_DIR_PREFIX="/tmp/.uploadMinidumps"
    sleep 5
fi

if [ "$DEVICE_TYPE" = "broadband" ];then
     PORTAL_URL="rdkbcrashportal.stb.r53.xcal.tv"
     REQUEST_TYPE=18
else
     PORTAL_URL=$(tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalSTBUrl 2>&1)
     if [ -z "$PORTAL_URL" ]; then
         PORTAL_URL="crashportal.stb.r53.xcal.tv"
     fi
     REQUEST_TYPE=17
fi

DENY_UPLOADS_FILE="/tmp/.deny_dump_uploads_till"
ON_STARTUP_DUMPS_CLEANED_UP_BASE="/tmp/.on_startup_dumps_cleaned_up"

UseCodebig=0
CodebigAvailable=0

if [ -f /usr/bin/GetServiceUrl ]; then
    if [ "$DEVICE_TYPE" == "broadband" ]; then
        #we are swaping dmcli and syscfg because dmcli will not work once rbus is down
        logMessage "Checking for CodeBig Support through syscfg"
        CodeBigFirst=`syscfg get CodeBigFirstEnabled`
        CodebigAvailable=1
        if [ "$CodeBigFirst" = "" -a "$BOX_TYPE" = "XB3" ]; then
            logMessage "syscfg value got null, it may be due to calling script from atom side"
            CodeBigFirst=`rpcclient $ARM_ARPING_IP "syscfg get CodeBigFirstEnabled" | cut -d$'\n' -f4`
            if [ "$CodeBigFirst" = "" ];then
                logMessage "Checking for CodeBig Support through dmcli"
                CodeBigFirst=`dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CodeBigFirst.Enable | grep value`
                CodeBigFirst=`echo $CodeBigFirst | cut -d ":" -f 3 | tr -d ' '`
            fi
        fi
        if [ "$CodeBigFirst" = "true" ]; then
            logMessage "CoreUpload:CodebigFirst is enabled"
            UseCodebig=1
        else
            logMessage "CoreUpload:CodebigFirst is disabled"
            IsDirectBlocked
            UseCodebig=$?
        fi
    else
        IsDirectBlocked
        UseCodebig=$?
    fi
fi

encryptionEnable=false
if [ "$DEVICE_TYPE" == "broadband" ]; then
    #we are swaping dmcli and syscfg because dmcli will not work once rbus is down
    logMessage "Checking for Encryption Support through syscfg"
    encryptionEnable=`syscfg get encryptcloudupload`
    if [ "$encryptionEnable" = "" -a "$BOX_TYPE" = "XB3" ]; then
        logMessage "syscfg value got null, it may be due to calling script from atom side"
        encryptionEnable=`rpcclient $ARM_ARPING_IP "syscfg get encryptcloudupload" | cut -d$'\n' -f4`
        if [ "$encryptionEnable" = "" ];then
            logMessage "Checking for Encryption Support through dmcli"
            encryptionEnable=`dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EncryptCloudUpload.Enable | grep value`
            encryptionEnable=`echo $encryptionEnable | cut -d ":" -f 3 | tr -d ' '`
        fi
    fi
elif [ -f /etc/os-release ]; then
    encryptionEnable=`tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EncryptCloudUpload.Enable 2>&1 > /dev/null`
fi

# append timestamp in seconds to $TIMESTAMP_FILENAME
# Uses globals: TIMESTAMP_FILENAME
logUploadTimestamp()
{
    if [ "$BUILD_TYPE" = "prod" ]; then
        date +%s >> "$TIMESTAMP_FILENAME"
        truncateTimeStampFile
    fi
}

# truncate $TIMESTAMP_FILENAME to 15 lines. We won't need more.
# Protected by create_lock_or_wait "$TIMESTAMP_FILENAME"
# Uses globals: TIMESTAMP_FILENAME
truncateTimeStampFile()
{
    # just in case there is no file yet
    touch "$TIMESTAMP_FILENAME" && chmod a+rw "$TIMESTAMP_FILENAME"

    tail -n 10 "$TIMESTAMP_FILENAME" > "${TIMESTAMP_FILENAME}_tmp"
    mv "${TIMESTAMP_FILENAME}_tmp" "$TIMESTAMP_FILENAME"
}

# Crash rate limit is reached if the 10th latest tarball was uploaded more then 10 minutes ago.
# Protected by create_lock_or_wait "$TIMESTAMP_FILENAME"
# Uses globals: TIMESTAMP_FILENAME
isUploadLimitReached()
{
    local limit_seconds=600
    touch "$TIMESTAMP_FILENAME" && chmod a+rw "$TIMESTAMP_FILENAME"

    local lines_count="$( wc -l < "$TIMESTAMP_FILENAME" )"
    if [ "$lines_count" -lt 10 ]; then
        # too few lines. Limit not reached. Return false.
        return 1
    fi

    local tenth_newest_crash_time=$( head -n1 "$TIMESTAMP_FILENAME" | awk '{print $1}' )
    local now=$( date "+%s" )

    if [ $(( now - tenth_newest_crash_time )) -lt $limit_seconds ]; then
        # limit reached. Return true.
        logMessage "Not uploading the dump. Too many dumps."
        return 0
    else
        return 1
    fi
}

# Set recovery time to Now + 10 minutes
# Uses globals: DENY_UPLOADS_FILE
setRecoveryTime()
{
    local current_time_sec="$( date +%s )"
    local dont_upload_for_sec=600
    echo $(( current_time_sec + dont_upload_for_sec )) > "$DENY_UPLOADS_FILE"
}

# true if upload denial time is unset or not reached
# Uses globals: DENY_UPLOADS_FILE
isRecoveryTimeReached()
{
    if [ ! -f "$DENY_UPLOADS_FILE" ]; then
      return 0
    fi

    local upload_denied_till="$( cat "$DENY_UPLOADS_FILE" )"

    # check if contents of the file are valid
    case $upload_denied_till in
        ''|*[!0-9]*) return 0 ;;
        *) true ;;
    esac

    local now="$( date +%s )"
    if [ "$now" -gt "$upload_denied_till" ]; then
        return 0
    fi

    return 1
}

# Removes unprocessed dumps that are waiting in the queue
# Uses globals: WORKING_DIR, DUMPS_EXTN
removePendingDumps()
{
    find "$WORKING_DIR" -name "$DUMPS_EXTN" -o -name "*.tgz" |
      while read file; do
          logMessage "Removing $file because upload limit has been reached or build is blacklisted or TelemetryOptOut is set"
          rm -f $file
      done
}

# Marks archive as crashlooped and uploads it to Crash Portal
# Arg 1: relative path for tgz to process
markAsCrashLoopedAndUpload()
{
    local tgz_name="$1"
    local new_tgz_name=$( echo $tgz_name | sed -e 's|.dmp.tgz$|.crashloop.dmp.tgz|g' )
    logMessage "Renaming $tgz_name to $new_tgz_name"
    mv $tgz_name $new_tgz_name
    coreUpload $new_tgz_name $PORTAL_URL $CRASH_PORTAL_PATH
}

############ Blacklist functions begin
# Downloads blacklist from S3, and saves the file to /opt/blacklist.txt.
# Blacklist will only be downloaded if there is no /opt/blacklist.txt, or it's modification date is older then 1 day.
downloadBlacklist()
{

    if [ "$DEVICE_TYPE" != "broadband" ]; then
        s3bucketurl=$(tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.S3BucketUrl 2>&1)
        if [ -z "$s3bucketurl" ]; then
            s3bucketurl="s3.amazonaws.com"
        fi
    fi

    if [[ ! -f $BLACKLIST_PATH ]] || [[ $(expr $(date +%s) - $(stat -c %Y $BLACKLIST_PATH)) -ge 86400 ]]; then
        logMessage "Downloading blacklisted signature list from http://${s3bucketurl}/ccp-stbcrashes/BLACKLISTS/blacklist.txt."
        if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
            curl --cert-status --connect-timeout 10 --max-time 30 https://${s3bucketurl}/ccp-stbcrashes/BLACKLISTS/blacklist.txt -o $BLACKLIST_PATH
        else
            curl --connect-timeout 10 --max-time 30 https://${s3bucketurl}/ccp-stbcrashes/BLACKLISTS/blacklist.txt -o $BLACKLIST_PATH
        fi
    fi
}

isBuildBlacklisted()
{
    if [ "$DEVICE_TYPE" = "broadband" ];then
        BLACKLIST_PATH="/nvram/blacklist.txt"
    else
        BLACKLIST_PATH="/opt/blacklist.txt"
    fi
    downloadBlacklist
    if [ ! -f $BLACKLIST_PATH ]; then
        return 255
    fi
    local blacklist=$(cat $BLACKLIST_PATH)

    # get version
    local version=$(grep 'imagename:' /version.txt|sed -e 's?imagename:??g')

    if [ -z "$version" ]; then
        return 255
    fi

    local build_name
    for build_name in $blacklist; do
        if [ "$build_name" = "$version" ]; then
            return 0
        fi
    done

    return 255
}
############ Blacklist functions end

# Note: This is not protected by the lock below.
TIMESTAMP_FILENAME="/tmp/.${DUMP_NAME}_upload_timestamps"

# Will wait if unable to create lock and 4th parameter is "wait_for_lock".
if [ "$WAIT_FOR_LOCK" = "wait_for_lock" ]; then
    create_lock_or_wait $LOCK_DIR_PREFIX
else
    create_lock_or_exit $LOCK_DIR_PREFIX
fi

#defer code upload for 8 mins of uptime to avoid CPU load during bootup(Only for Video devices)
if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ]; then
    uptime_val=`cat /proc/uptime | awk '{ split($1,a,".");  print a[1]; }'`
    if [ $uptime_val -lt $FOUR_EIGHTY_SECS ]; then
        sleep_time=$((FOUR_EIGHTY_SECS - uptime_val))
        logMessage "Deferring reboot for $sleep_time seconds"
        sleep $sleep_time
    fi
fi

if [ "$DEVICE_TYPE" != "broadband" ];then
    # wait the internet connection once after boot
    NETWORK_TESTED="/tmp/internet_tested"
    NETWORK_TEST_ITERATIONS=18
    NETWORK_TEST_DELAY=10
    SYSTEM_TIME_TEST_ITERATIONS=10
    SYSTEM_TIME_TEST_DELAY=1
    SYSTEM_TIME_TESTED="/tmp/stt_received"
    IPV4_FILE="/tmp/estb_ipv4"
    IPV6_FILE="/tmp/estb_ipv6"
    counter=1

    if [ ! -f "$NETWORK_TESTED" ]; then
        while [ $counter -le $NETWORK_TEST_ITERATIONS ]; do
            logMessage "Testing the internet connection, iteration $counter"

            estbIp=`getIPAddress`
            if [ "X$estbIp" = "X" ];then
                logMessage "Waiting the IP."
                sleep $NETWORK_TEST_DELAY
            else
                logMessage "Current IP address: '$estbIp', default IP: '$DEFAULT_IP'"
                if [ "$IPV6_ENABLED" = "true" ]; then
                    if [ ! -f "$IPV4_FILE" ] && [ ! -f "$IPV6_FILE" ]; then
                        logMessage "Waiting the IPv6."
                        sleep $NETWORK_TEST_DELAY
                    elif [ "Y$estbIp" = "Y$DEFAULT_IP" ] && [ -f "$IPV4_FILE" ]; then
                        logMessage "Waiting the IPv6."
                        sleep $NETWORK_TEST_DELAY
                    else
                        logMessage "Internet is up."
                        counter=$(( NETWORK_TEST_ITERATIONS + 1 ))
                    fi
                else
                    if [ "Y$estbIp" = "Y$DEFAULT_IP" ]; then
                        logMessage "Waiting the IPv4."
                        sleep $NETWORK_TEST_DELAY
                    else
                        logMessage "Internet is up."
                        counter=$(( NETWORK_TEST_ITERATIONS + 1 ))
                    fi
                fi
            fi

            if [ $counter = $NETWORK_TEST_ITERATIONS ]; then
                 logMessage "Continue without IP."
            fi

            counter=$(( counter + 1 ))
        done
        touch $NETWORK_TESTED
    else
        logMessage "The network has already been tested"
    fi

    logMessage "IP acquistion completed, Testing the system time is received"
    if [ ! -f "$SYSTEM_TIME_TESTED" ]; then
        while [ $counter -le $SYSTEM_TIME_TEST_ITERATIONS ]; do
            if [ ! -f "$SYSTEM_TIME_TESTED" ]; then
                logMessage "Waiting for STT, iteration $counter"
                sleep $SYSTEM_TIME_TEST_DELAY
            else
                logMessage "Received $SYSTEM_TIME_TESTED flag"
                break
            fi

            if [ $counter = $SYSTEM_TIME_TEST_ITERATIONS ]; then
                logMessage "Continue without $SYSTEM_TIME_TESTED flag"
            fi

            counter=$(( counter + 1 ))
        done
    else
        logMessage "Received $SYSTEM_TIME_TESTED flag"
    fi
else
    network_commn_status
    #WAN_STATE=`sysevent get wan-status`
    #EROUTER_IP=`ifconfig $WAN_INTERFACE | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
    #while [ "$WAN_INTERFACE" != "started" ] && [ "$EROUTER" != "" ];do
    #    sleep 5
    #    WAN_STATE=`sysevent get wan-status`
    #    if [ ! "$EROUTER_IP" ];then 
    #        EROUTER_IP=`ifconfig $WAN_INTERFACE | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
    #    fi
    #done
fi
# Upon exit, remove locking
trap finalize EXIT

if isBuildBlacklisted; then
    logMessage "Skipping upload. The build is blacklisted."
    removePendingDumps
    exit
fi

#skip upload if opt out is set to true
getOptOutStatus
opt_out=$?
if [ $opt_out -eq 1 ]; then
    logMessage "Coreupload is disabled as TelemetryOptOut is set"
    removePendingDumps
    exit
fi

x=0
while [ ! -f /tmp/coredump_mutex_release ] && [ "$DUMP_FLAG" == "1" ]; do
     logMessage "Waiting for Coredump Completion"
     sleep 3
     x=`expr $x + 1`
     if [ $x -eq 7 ];then break; fi
done

if [ -f /tmp/set_crash_reboot_flag ];then
      logMessage "Skipping upload, Since Box is Rebooting now"
      if [ "$IS_T2_ENABLED" == "true" ]; then
            t2CountNotify "SYST_INFO_CoreUpldSkipped"
      fi
      logMessage "Upload will happen on next reboot"
      exit 0
fi

# Get the MAC address of the box
MAC=`getMacAddressOnly`
# Ensure MAC is not empty
checkMAC

logMessage "Mac address is $MAC"

count=`find "$WORKING_DIR" -name "$DUMPS_EXTN" | wc -l`
if [ $count -eq 0 ]; then logMessage "No ${DUMP_NAME} for uploading" ; exit 0; fi

cleanup
logMessage "Portal URL: $PORTAL_URL"

codebigUpload()
{    
    SIGN_CMD="GetServiceUrl $REQUEST_TYPE \"$1\""
    eval $SIGN_CMD > /tmp/.signedRequest
    if [ -s /tmp/.signedRequest ]
    then
        echo "CodeBig Log upload - GetServiceUrl success"
    else
        echo "CodeBig Log upload - GetServiceUrl failed"
        return 1
    fi
    CB_CLOUD_URL=`cat /tmp/.signedRequest`
    rm -f /tmp/.signedRequest
    
    authorizationHeader=`echo $CB_CLOUD_URL | sed -e "s|&|\", |g" -e "s|=|=\"|g" -e "s|.*oauth_consumer_key|oauth_consumer_key|g"`
    authorizationHeader="Authorization: OAuth realm=\"\", $authorizationHeader\""
    serverUrl=`echo $CB_CLOUD_URL | sed -e 's|&oauth_consumer_key.*||g' -e 's|file=.*&filename|filename|g' -e 's|%2F|/|g'`

    if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
        CURL_CMD="curl -v $TLS $INTERFACE_OPTION -w '%{http_code}\n' -d \"file=$coreFile\" -H '$authorizationHeader'  \"$serverUrl&user=ccpstbscp\" --cert-status --connect-timeout $CURL_UPLOAD_TIMEOUT"
        logMessage "Upload string: curl -v $TLS $INTERFACE_OPTION -w '%{http_code}\n' -d \"file=$coreFile\" -H <Hidden authorization-header> \"$serverUrl&user=ccpstbscp\" --cert-status --connect-timeout $CURL_UPLOAD_TIMEOUT"
    else
        CURL_CMD="curl -v $TLS $INTERFACE_OPTION -w '%{http_code}\n' -d \"file=$coreFile\" -H '$authorizationHeader'  \"$serverUrl&user=ccpstbscp\" --connect-timeout $CURL_UPLOAD_TIMEOUT"
        logMessage "Upload string: curl -v $TLS $INTERFACE_OPTION -w '%{http_code}\n' -d \"file=$coreFile\" -H <Hidden authorization-header> \"$serverUrl&user=ccpstbscp\" --connect-timeout $CURL_UPLOAD_TIMEOUT"
    fi
    eval $CURL_CMD > $HTTP_CODE
    TLSRet=$?
}


uploadToS3()
{
    URLENCODE_STRING=""
    local file=$(basename $1)
    #logMessage "uploadToS3 '$(readlink $1)'"
    logMessage "uploadToS3 $1"
    if [ $file = mac* ]; then
    # Update upload time to corefile from uploadToS3 function.
    corefiletime=`echo $file | awk -F '_' '{print substr($2,4)}'`
    logMessage "$DUMP_NAME file timestamp received to uploadToS3: $corefiletime"
    else
    # Update upload time to corefile from uploadToS3 function.
    corefiletime=`echo $file | awk -F '_' '{print substr($3,4)}'`
    logMessage "$DUMP_NAME file timestamp received to uploadToS3: $corefiletime"
    fi
    uploadcurtime=`date +%Y-%m-%d-%H-%M-%S`
    logMessage "$DUMP_NAME file timestamp before upload: $uploadcurtime"
    
    updatedfile=`echo $file | sed "s/$corefiletime/$uploadcurtime/g"`
    logMessage "$DUMP_NAME file to be uploaded: `echo $updatedfile`"
    
    if [ -f $WORKING_DIR"/"$file ]; then
        logMessage "Renaming the $DUMP_NAME file under $WORKING_DIR"
        mv $WORKING_DIR"/"$file $WORKING_DIR"/"$updatedfile
        S3_FILENAME=$updatedfile
    else
        logMessage "$DUMP_NAME file: $file not found under $WORKING_DIR folder..!!!"
    fi

    local app=${updatedfile%%.signal*}
    #get signed parameters from server
    local OIFS=$IFS
    IFS=$'\n'
    
    if [ "$DEVICE_TYPE" != "broadband" ]; then
        S3_AMAZON_SIGNING_URL=$(tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.S3SigningUrl 2>&1)
        if [ -z "$S3_AMAZON_SIGNING_URL" ];then
            . /etc/device.properties
        fi
    fi
    
    logMessage "[$0]: S3 Amazon Signing URL: $S3_AMAZON_SIGNING_URL"   
    CurrentVersion=`grep imagename /$VERSION_FILE | cut -d':' -f2`

    IF_OPTION=""
    if [ "$DEVICE_TYPE" = "broadband" ] && [ "$MULTI_CORE" = "yes" ];then
          core_output=`get_core_value`
          if [ "$core_output" = "ARM" ];then 
                IF_OPTION="$ARM_INTERFACE"
          fi
    fi

    logMessage "RFC_EncryptCloudUpload_Enable:$encryptionEnable"
    if [ "$encryptionEnable" == "true" ]; then
        S3_MD5SUM="$(openssl md5 -binary < $updatedfile | openssl enc -base64)"
        URLENCODE_STRING="--data-urlencode \"md5=$S3_MD5SUM\""
    fi
    mTlsCrashdumpUpload="false"
    bootstrapSsrUrl=""
    if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ]; then
       mTlsCrashdumpUpload=$(tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.MTLS.mTlsCrashdumpUpload.Enable 2>&1 > /dev/null)
       bootstrapSsrUrl=$(tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Bootstrap.SsrUrl 2>&1 > /dev/null)
       logMessage "mTlsCrashdumpUpload:$mTlsCrashdumpUpload"
    fi
    if [ "$bootstrapSsrUrl" ]; then
       S3_AMAZON_SIGNING_URL="$bootstrapSsrUrl/cgi-bin/upload_dump.cgi"
       logMessage "Overriding the S3 Amazon SIgning URL: $S3_AMAZON_SIGNING_URL"
    fi
    #Setting MTLS Creds for S3 Upload
    if [ "$FORCE_MTLS" = "true" ] || [ "$mTlsCrashdumpUpload" = "true" ]; then
       logMessage "MTLS prefered for CrashdumpUpload"
       CERT=`getMtlsCreds uploadDumps.sh /etc/ssl/certs/cpe-clnt.xcal.tv.cert.pem /tmp/uydrgopwxyem`
    else
       CERT=""
    fi
    if [ ! -f /etc/ssl/certs/cpe-clnt.xcal.tv.cert.pem ]; then
       logMessage "Using Xpki cert for CrashdumpUpload"
    fi
    if [ ! -z "$IF_OPTION" ]; then
        if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
            CURL_CMD="curl $CERT -s $TLS --interface $IF_OPTION --cert-status -o /tmp/signed_url -w \"%{http_code}\" --data-urlencode "filename=\"$updatedfile\""\
                                             --data-urlencode "firmwareVersion=$CurrentVersion"\
                                             --data-urlencode "env=$BUILD_TYPE"\
                                             --data-urlencode "model=$modNum"\
                                             --data-urlencode "type=$DUMP_NAME" \
                                             $URLENCODE_STRING\
                                             "$S3_AMAZON_SIGNING_URL""
        else
            CURL_CMD="curl $CERT -s $TLS --interface $IF_OPTION -o /tmp/signed_url -w \"%{http_code}\" --data-urlencode "filename=\"$updatedfile\""\
                                             --data-urlencode "firmwareVersion=$CurrentVersion"\
                                             --data-urlencode "env=$BUILD_TYPE"\
                                             --data-urlencode "model=$modNum"\
                                             --data-urlencode "type=$DUMP_NAME" \
                                             $URLENCODE_STRING\
                                             "$S3_AMAZON_SIGNING_URL""
        fi
    else
       CURL_CMD="curl $CERT -s $TLS -o /tmp/signed_url -w \"%{http_code}\" --data-urlencode "filename=\"$updatedfile\""\
                --data-urlencode "firmwareVersion=$CurrentVersion"\
                --data-urlencode "env=$BUILD_TYPE"\
                --data-urlencode "model=$modNum"\
                --data-urlencode "type=$DUMP_NAME" \
                $URLENCODE_STRING\
                "$S3_AMAZON_SIGNING_URL""

        if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
            CURL_CMD="$CURL_CMD --cert-status"
        fi
    fi
    status=`eval $CURL_CMD > $HTTP_CODE`
    local ec=$?
    IFS=$OIFS
    logMessage "[$0]: Execution Status: $ec, HTTP SIGN URL Response: `cat $HTTP_CODE`"
    if [ $ec -eq 0 ]; then
        if [ -z "$1" ]; then
            ec=1
            logMessage "[$0]: S3 Amazon Signing Request Failed..!"
	    if [ "$IS_T2_ENABLED" == "true" ]; then
		    t2CountNotify "SYST_ERR_S3signing_failed"
            fi
        else
            #make params shell-safe
            local validDate=`sanitize "$updatedfile"`
            local auth=`sanitize "$2"`
            local remotePath=`sanitize "$3"`
            logMessage "Safe params: $validDate -- $auth -- $remotePath"
            tlsMessage="with TLS1.2"
            logMessage "Attempting TLS1.2 connection to Amazon S3"
            S3_URL=$(cat /tmp/signed_url)

            if [ "$encryptionEnable" != "true" ]; then
                S3_URL=\"$S3_URL\"
            fi
            if [ "$DEVICE_TYPE" = "broadband" ] && [ "$MULTI_CORE" = "yes" ];then
                core_output=`get_core_value`
                if [ "$core_output" = "ARM" ];then
                    if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
                        CURL_CMD="curl $CERT -v -fgL --tlsv1.2 --cert-status --interface $ARM_INTERFACE -T \"$updatedfile\" -w \"%{http_code}\" $S3_URL"
                    else
                        CURL_CMD="curl $CERT -v -fgL --tlsv1.2 --interface $ARM_INTERFACE -T \"$updatedfile\" -w \"%{http_code}\" $S3_URL"
                    fi
                else
                    if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
                        CURL_CMD="curl $CERT -v -fgL --tlsv1.2 --cert-status -T \"$updatedfile\" -w \"%{http_code}\" $S3_URL"
                    else
                        CURL_CMD="curl $CERT -v -fgL --tlsv1.2 -T \"$updatedfile\" -w \"%{http_code}\" $S3_URL"
                    fi
                fi
            else
                CURL_CMD="curl $CERT -v -fgL $TLS -T \"$updatedfile\" -w \"%{http_code}\" $S3_URL"
                if [ -f $EnableOCSPStapling ] || [ -f $EnableOCSP ]; then
                    CURL_CMD=$CURL_CMD --cert-status
                fi
            fi
            CURL_REMOVE_HEADER=`echo $CURL_CMD | sed "s/AWSAccessKeyId=.*Signature=.*&//g;s/-H .*https/https/g"`
            CURL_REMOVE_CERT_KEYS=`echo $CURL_REMOVE_HEADER |sed 's/devicecert_1.*-v/devicecert_1.pk12<masked> -v/' |sed 's/staticXpkiCrt.*-v/staticXpkiCrt.pk12<masked> -v/'`
            logMessage "URL_CMD: $CURL_REMOVE_CERT_KEYS"
            result= eval $CURL_CMD > $HTTP_CODE
            ec=$?
            rm /tmp/signed_url
            logMessage "Execution Status:$ec HTTP Response code: `cat $HTTP_CODE` "
        fi
    fi
    if [ $ec -ne 0 ]; then
        logMessage "Curl finished unsuccessfully! Error code: $ec"
        if [ "$IS_T2_ENABLED" == "true" ]; then
            t2CountNotify "SYS_ERROR_S3CoreUpload_Failed"
	    if [ "$ec" -eq 6 ]; then
                 t2CountNotify "SYST_INFO_CURL6"
            fi
        fi
     else
        logMessage "S3 ${DUMP_NAME} Upload is successful $tlsMessage"
        if [ "$IS_T2_ENABLED" == "true" ]; then
            t2CountNotify "SYS_INFO_S3CoreUploaded"
        fi
        #Removing updated timestamp minidump/coredump file since processDumps func will remove old timestamp minidump/coredump file.
        logMessage "Removing uploaded $DUMP_NAME file $updatedfile"
        rm -rf $updatedfile
     fi
    return $ec
}

VERSION_FILE="version.txt"
VERSION_FILE_PATH="/${VERSION_FILE}"
boxType=$BOX_TYPE
if [ "$DEVICE_TYPE" = "broadband" ];then
    #we are swaping dmcli and device.properties since dmcli will not work once rbus service is down
    modNum=`cat /etc/device.properties | grep MODEL_NUM | cut -f2 -d=`
    if [ ! "$modNum" ];then
        modNum=`dmcli eRT getv Device.DeviceInfo.ModelName | grep value | cut -d ":" -f 3 | tr -d ' ' `
    fi
else
    modNum="$(grep -i 'imagename:' ${VERSION_FILE_PATH} | head -n1 | cut -d ':' -f2 | cut -d '_' -f1)"
fi
# Ensure modNum is not empty
checkParameter modNum

if [ "$BUILD_TYPE" != "prod" ]; then
# if the build type is DEV or VBN we should add all logs to the package
    #Receiver Logs
    STBLOG_FILE=$LOG_PATH/receiver.log
    #OCAP Logs
    if [ "$DEVICE_TYPE" = "mediaclient" ]; then
        OCAPLOG_FILE=$LOG_PATH/rmfstr_log.txt
    else
        OCAPLOG_FILE=$LOG_PATH/ocapri_log.txt
    fi
    #Thread dump
    THREAD_DUMP=threaddump.txt
    #Message.txt
    MESSAGE_TXT=$LOG_PATH/messages.txt
    #app_status.log
    APP_STATUS_LOG=$LOG_PATH/app_status_backup.log
    #applications.log
    APP_LOG=$LOG_PATH/applications.log
    #cef.log
    CEF_LOG=$LOG_PATH/cef.log
    CRASHED_URL_FILE=$LOG_PATH/crashed_url.txt
    WPEFRAMEWORK_LOG=$LOG_PATH/wpeframework.log
else
    if [ "$DUMP_FLAG" != "1" ]; then
    # if the build type is PROD and script is in minidump's mode we should add receiver log and applications.log
        #Receiver Logs
        STBLOG_FILE=/opt/logs/receiver.log
        #applications.log
        APP_LOG=$LOG_PATH/applications.log
        #cef.log
        CEF_LOG=$LOG_PATH/cef.log
        #rmf_str.log
        if [ "$DEVICE_TYPE" = "mediaclient" ]; then
            OCAPLOG_FILE=$LOG_PATH/rmfstr_log.txt
        fi
        CRASHED_URL_FILE=$LOG_PATH/crashed_url.txt
        WPEFRAMEWORK_LOG=$LOG_PATH/wpeframework.log
    fi
fi

# Receiver binary is used to calculate SHA1 marker which is used to find debug file for the coredumps
sha1=`getSHA1 /version.txt`
# Ensure sha1 is not empty
checkParameter sha1

logMessage "buildID is $sha1"

if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ];then
    if [ ! -z "$STBLOG_FILE" -a -f "$STBLOG_FILE" ]; then
        stbModTS=`getLastModifiedTimeOfFile $STBLOG_FILE`
        # Ensure timestamp is not empty
        checkParameter stbModTS
        stbLogFile=`setLogFile $sha1 $MAC $stbModTS $boxType $modNum $STBLOG_FILE`
    fi
    if [ ! -z "$OCAPLOG_FILE" -a -f "$OCAPLOG_FILE" ]; then
        ocapLogModTS=`getLastModifiedTimeOfFile $OCAPLOG_FILE`
        # Ensure timestamp is not empty
        checkParameter ocapLogModTS
        ocapLogFile=`setLogFile $sha1 $MAC $ocapLogModTS $boxType $modNum $OCAPLOG_FILE`
    fi
    if [ ! -z "$APP_STATUS_LOG" -a -f "$APP_STATUS_LOG" ] ; then
        appStatusLogModTS=`getLastModifiedTimeOfFile $APP_STATUS_LOG`
        # Ensure timestamp is not empty
        checkParameter appStatusLogModTS
        appStatusLogFile=`setLogFile $sha1 $MAC $appStatusLogModTS $boxType $modNum $APP_STATUS_LOG`
    fi
    if [ ! -z "$MESSAGE_TXT" -a -f "$MESSAGE_TXT" ]; then
       messagesTxtModTS=`getLastModifiedTimeOfFile $MESSAGE_TXT`
       # Ensure timestamp is not empty
       checkParameter messagesTxtModTS
       messagesTxtFile=`setLogFile $sha1 $MAC $messagesTxtModTS $boxType $modNum $MESSAGE_TXT`
    fi
    if [ ! -z "$APP_LOG" -a -f "$APP_LOG" ]; then
       appLogModTS=`getLastModifiedTimeOfFile $APP_LOG`
       # Ensure timestamp is not empty
       checkParameter appLogModTS
       appLogFile=`setLogFile $sha1 $MAC $appLogModTS $boxType $modNum $APP_LOG`
    fi
    if [ ! -z "$CEF_LOG" -a -f "$CEF_LOG" ]; then
       cefLogModTS=`getLastModifiedTimeOfFile $CEF_LOG`
       # Ensure timestamp is not empty
       checkParameter cefLogModTS
       cefLogFile=`setLogFile $sha1 $MAC $cefLogModTS $boxType $modNum $CEF_LOG`
    fi
    if [ ! -z "$CRASHED_URL_FILE" -a -f "$CRASHED_URL_FILE" ]; then
       crashedUrlFile=$CRASHED_URL_FILE
    fi
    if [ ! -z "$WPEFRAMEWORK_LOG" -a -f "$WPEFRAMEWORK_LOG" ]; then
     wpeLogModTS=`getLastModifiedTimeOfFile $WPEFRAMEWORK_LOG`
     # Ensure timestamp is not empty
     checkParameter wpeLogModTS
     wpeLogFile=`setLogFile $sha1 $MAC $wpeLogModTS $boxType $modNum $WPEFRAMEWORK_LOG`
    fi
fi

# use for loop read all nameservers
logFileCopy()
{
    line_count=5000
    if [ "$BUILD_TYPE" = "prod" ]; then
       line_count=500
    fi

    if [ "$DUMP_FLAG" != "0" ]; then
        if [ ! -z "$STBLOG_FILE" -a -f "$STBLOG_FILE" ]; then
            tail -n ${line_count} $STBLOG_FILE > $stbLogFile
        fi
        if [ ! -z "$OCAPLOG_FILE" -a -f "$OCAPLOG_FILE" ]; then
            tail -n ${line_count} $OCAPLOG_FILE > $ocapLogFile
        fi
        if [ ! -z "$WPEFRAMEWORK_LOG" -a -f "$WPEFRAMEWORK_LOG" ]; then
            tail -n ${line_count} $WPEFRAMEWORK_LOG > $wpeLogFile
        fi
    fi
    if [ ! -z "$MESSAGE_TXT" -a -f "$MESSAGE_TXT" ]; then
        tail -n ${line_count} $MESSAGE_TXT > $messagesTxtFile
    fi
    if [ ! -z "$APP_STATUS_LOG" -a -f "$APP_STATUS_LOG" ]; then
        tail -n ${line_count} $APP_STATUS_LOG > $appStatusLogFile
    fi
    if [ ! -z "$APP_LOG" -a -f "$APP_LOG" ]; then
        tail -n ${line_count} $APP_LOG > $appLogFile
    fi
    if [ ! -z "$CEF_LOG" -a -f "$CEF_LOG" ]; then
        tail -n 500 $CEF_LOG > $cefLogFile
    fi
}

if [ ! -d $WORKING_DIR ]; then exit 0; fi
cd $WORKING_DIR

shouldProcessFile()
{
    fName=$1
    # always upload minidumps
    if [ "$DUMP_FLAG" != "1" ]; then
        echo 'true'
        return
    # upload cores even for prod if it is not Receiver
    elif [[ -n "${fName##*Receiver*}" ]]; then
        echo 'true'
        return
    # upload cores not for prod
    elif [ "$BUILD_TYPE" != "prod" ]; then
        echo 'true'
        return
    else
    # it's prod coredump, not mpeos and not discovery
    logMessage "Not processing $fName"
        echo 'false'
        return
    fi
}

get_crashed_log_file()
{
    file="$1"
    pname=`echo $file | awk -F_ '{print $1}'`
    pname=${pname#"./"} #Remove ./ from the dump name
    logMessage "Process crashed = $pname"
    log_files=`awk -v proc="$pname" -F= '$1 ~ proc {print $2}' $LOGMAPPER_FILE`
    logMessage "Crashed process log file(s): $log_files"
    for i in $(echo $log_files | sed -n 1'p' | tr ',' '\n'); do
        echo "$LOG_PATH/$i" >> $LOG_FILES
    done
}

add_crashed_log_file()
{
    files="$@"

    line_count=5000
    if [ "$BUILD_TYPE" = "prod" ]; then
       line_count=500
    fi

    while read line
    do
        if [ ! -z "$line" -a -f "$line" ]; then
            logModTS=`getLastModifiedTimeOfFile $line`
            checkParameter logModTS
            process_log=`setLogFile $sha1 $MAC $logModTS $boxType $modNum $line`
            tail -n ${line_count} $line > $process_log
            logMessage "Adding File: $process_log to minidump tarball"
            files="$files $process_log"
        fi
    done < $LOG_FILES
    rm -rf $LOG_FILES
}

processDumps()
{
    # wait for app buffers are flushed
    type flushLogger &> /dev/null && flushLogger || sleep 2

    find -name "$DUMPS_EXTN" -type f | while read f;
    do
        local f1=$(echo "$f" | sed -e 's/[^/a-zA-Z0-9 ._-]//g')
        if [ -z "$f1" ]; then
            rm -f "$f"
            continue
        elif [ "$f1" != "$f" ]; then
            mv "$f" "$f1"
            f="$f1"
        fi
        if [ "$DUMP_FLAG" == "0" ]; then
            get_crashed_log_file "$f"
        fi
        if [ -f "$f" ]; then
            #last modification date of a core dump, to ease refusing of already uploaded core dumps on a server side
            modDate=`getLastModifiedTimeOfFile $f`
            if [ -z "$CRASHTS" ]; then
                  CRASHTS=$modDate
                  # Ensure timestamp is not empty
                  checkParameter CRASHTS
            fi

            if [ "$DUMP_FLAG" == "1" ] ; then
                if echo $f | grep -q mpeos-main; then
                    #CRASHTS not reqd as minidump won't be uploaded for mpeos-main
                    dumpName=`setLogFile $sha1 $MAC $modDate $boxType $modNum $f`
                    logFileCopy 1
                else
                    dumpName=`setLogFile $sha1 $MAC $CRASHTS $boxType $modNum $f`
                    logFileCopy 0
                fi
		if [ "${#dumpName}" -ge "135" ]; then
		     #Removing the HEADER of the corefile due to ecryptfs limitation as file can't be open when it exceeds 140 characters.
	             dumpName="${dumpName#*_}"
		fi
                tgzFile=$dumpName".core.tgz"
            else
                dumpName=`setLogFile $sha1 $MAC $CRASHTS $boxType $modNum $f`
		if [ "${#dumpName}" -ge "135" ]; then
		     #Removing the HEADER of the corefile due to ecryptfs limitation as file can't be open when it exceeds 140 characters.
		     dumpName="${dumpName#*_}"
		fi
                if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ];then
                    logFileCopy 0
                fi
                tgzFile=$dumpName".tgz"
            fi

            mv $f $dumpName
            cp "/"$VERSION_FILE .

            logMessage "Size of the file: `ls -l $dumpName`"
            if [ "$DUMP_FLAG" == "1" ] ; then
                nice -n 19 tar -zcvf $tgzFile $dumpName $stbLogFile $ocapLogFile $messagesTxtFile $appStatusLogFile $appLogFile $cefLogFile $wpeLogFile $VERSION_FILE $CORE_LOG 2>&1 | logStdout
                if [ $? -eq 0 ]; then
                    logMessage "Success Compressing the files, $tgzFile $dumpName $stbLogFile $ocapLogFile $messagesTxtFile $appStatusLogFile $appLogFile $cefLogFile $wpeLogFile $VERSION_FILE $CORE_LOG "
                else
                    logMessage "Compression Failed ."
                fi

                if [ -f $tgzFile".txt" ]; then rm $tgzFile".txt"; fi
                if [ ! -z "$STBLOG_FILE" -a -f $STBLOG_FILE"_mpeos-main" ]; then
                    rm $STBLOG_FILE"_mpeos-main"
                fi
                if [ ! -z "$OCAPLOG_FILE" -a -f $OCAPLOG_FILE"_mpeos-main" ]; then
                    rm $OCAPLOG_FILE"_mpeos-main"
                fi
                if [ ! -z "$MESSAGE_TXT" -a -f $MESSAGE_TXT"_mpeos-main" ]; then
                    rm $MESSAGE_TXT"_mpeos-main"
                fi
                if [ ! -z "$APP_STATUS_LOG" -a -f $APP_STATUS_LOG"_mpeos-main" ]; then
                    rm $APP_STATUS_LOG"_mpeos-main"
                fi
                if [ ! -z "$APP_LOG" -a -f $APP_LOG"_mpeos-main" ]; then
                    rm $APP_LOG"_mpeos-main"
                fi
                if [ ! -z "$CEF_LOG" -a -f $CEF_LOG"_mpeos-main" ]; then
                    rm $CEF_LOG"_mpeos-main"
                fi
                if [ ! -z "$WPEFRAMEWORK_LOG" -a -f $WPEFRAMEWORK_LOG"_mpeos-main" ]; then
                    rm $WPEFRAMEWORK_LOG"_mpeos-main"
                fi
            else
                if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ]; then
                    files="$tgzFile $dumpName $VERSION_FILE $messagesTxtFile $appStatusLogFile $appLogFile $cefLogFile $CORE_LOG $crashedUrlFile"
                    if [ "$BUILD_TYPE" != "prod" ]; then
                        test -f $LOG_PATH/receiver.log && files="$files $LOG_PATH/receiver.log*"
                        test -f $LOG_PATH/thread.log && files="$files $LOG_PATH/thread.log"
                    else
                        test -f $LOG_PATH/receiver.log && files="$files $LOG_PATH/receiver.log"
                        test -f $LOG_PATH/receiver.log.1 && files="$files $LOG_PATH/receiver.log.1"
                    fi
                    add_crashed_log_file $files
                    nice -n 19 tar -zcvf $files 2>&1 | logStdout
                    if [ $? -eq 0 ]; then
                        logMessage "Success Compressing the files $files"
                    else
                        logMessage "Compression Failed."
                    fi
                elif [ "$DEVICE_TYPE" = "broadband" ]; then
                    files="$tgzFile $dumpName $VERSION_FILE $CORE_LOG"
                    add_crashed_log_file $files
                    nice -n 19 tar -zcvf $files 2>&1 | logStdout
                    if [ $? -eq 0 ]; then
                        logMessage "Success Compressing the files, $files"
                    else
                        logMessage "Compression Failed ."
                    fi
                else
                    echo "$0 New Model, need to add support..!"
                fi
            fi
            logMessage "Size of the compressed file: `ls -l $tgzFile`"

            rm $dumpName
            if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ]; then
                if [ "$DUMP_FLAG" != "0" ]; then
                    if [ ! -z "$STBLOG_FILE" -a -f "$STBLOG_FILE" ]; then
                        logMessage "Removing $stbLogFile"
                        rm $stbLogFile
                    fi
                    if [ ! -z "$OCAPLOG_FILE" -a -f "$OCAPLOG_FILE" ]; then
                        logMessage "Removing $ocapLogFile"
                        rm $ocapLogFile
                    fi
                    if [ ! -z "$WPEFRAMEWORK_LOG" -a -f "$WPEFRAMEWORK_LOG" ]; then
                        logMessage "Removing $wpeLogFile"
                        rm $wpeLogFile
                    fi
                fi
                if [ ! -z "$MESSAGE_TXT" -a -f "$MESSAGE_TXT" ]; then
                    logMessage "Removing $messagesTxtFile"
                    rm $messagesTxtFile
                fi
                if [ ! -z "$APP_STATUS_LOG" -a -f "$APP_STATUS_LOG" ]; then
                    logMessage "Removing $appStatusLogFile"
                    rm $appStatusLogFile
                fi
                if [ -f $WORKING_DIR"/"$VERSION_FILE ]; then
                    logMessage "Removing ${WORKING_DIR}/${VERSION_FILE}"
                    rm $WORKING_DIR"/"$VERSION_FILE
                fi
                if [ ! -z "$APP_LOG" -a -f "$APP_LOG" ]; then
                    logMessage "Removing $appLogFile"
                    rm $appLogFile
                fi
                if [ ! -z "$CEF_LOG" -a -f "$CEF_LOG" ]; then
                    logMessage "Removing $cefLogFile"
                    rm $cefLogFile
                fi
            fi
            if [ "$DUMP_FLAG" == "0" ]; then
                process_logs=`find $WORKING_DIR \( -iname "*.log*" -o -iname "*.txt*" \) -type f -print -exec rm -f {} \;`
                logMessage "Removing ${process_logs}"
            fi
        fi
    done

    if [ "$DUMP_FLAG" != "1" ]; then
        rm -f $LOG_PATH/thread.log
    fi

    find -name "$TARBALLS" -type f | while read f;
    do
        if [ -f $f ]; then
            # On reaching the crash rate limit we stop processing further crashes for 10 minutes
            # (until a so-called "recovery time"). Any crashes occurring before the recovery time get
            # discarded and set the recovery time to 10 minutes from now, i.e. shift it.
            # If a crash occurs after the recovery time, we resume normal minidump uploads.
            # This also uploads specially-crafted archive that tells Crash Portal about hitting the limit.
            if isRecoveryTimeReached; then
                rm -f "$DENY_UPLOADS_FILE"
            else
                logMessage "Shifting the recovery time forward."
                setRecoveryTime
                removePendingDumps
                exit
            fi
            if [ "$DUMP_NAME" = "minidump" ]; then
                if isUploadLimitReached; then
                    logMessage "Upload rate limit has been reached."
                    markAsCrashLoopedAndUpload $f
                    logMessage "Setting recovery time"
                    setRecoveryTime
                    removePendingDumps
                    exit
                fi
            else
                logMessage "Coredump File `echo $f`"
            fi
            S3_FILENAME=`echo ${f##*/}`
            count=1

            # upload to S3 amazon first
            logMessage "[$0]: $count: $DUMP_NAME S3 Upload "
            uploadToS3 "`echo $S3_FILENAME`" 
            status=$?
            while [ $count -le 3 ]
            do
                if [ -f /etc/waninfo.sh ]; then
                    ARM_INTERFACE=$(getWanInterfaceName)
                fi
                # S3 amazon fail over recovery
                count=`expr $count + 1`
                if [ $status -ne 0 ];then
                     logMessage "[$0]: Execution Status: $status, S3 Amazon Upload of $DUMP_NAME Failed"
                     logMessage "[$0]: $count: (Retry), $DUMP_NAME S3 Upload"
                     sleep 2
                     uploadToS3 "`echo $S3_FILENAME`"
                     status=$?
                else
                     logMessage "[$0]: $DUMP_NAME uploadToS3 SUCESS: status: $status"
		     if [ "$DUMP_NAME" == "minidump" ] && [ "$IS_T2_ENABLED" == "true" ]; then
			     t2CountNotify "SYST_INFO_minidumpUpld"
		     fi
                     break
                fi
            done
            if [ $status -ne 0 ];then
                  logMessage "[$0]: S3 Amazon Upload of $DUMP_NAME Failed..!"
                  logMessage "Removing file $S3_FILENAME"
                  rm -f $S3_FILENAME
                  exit 1
            else
                  echo "[$0]: Execution Status: $status, S3 Amazon Upload of $DUMP_NAME Success"
            fi
            logMessage "Removing file $S3_FILENAME"
            rm -f $S3_FILENAME
            logUploadTimestamp
        fi
    done
}

if [ "$DUMP_FLAG" == "0" ]; then
    processDumps
else
    for i in 1 2 3; do
        files=$(find . -name "$DUMPS_EXTN" | head -n1)
        if [ -z "$files" ]; then
            break
        fi
        processDumps
    done
fi

finalize

