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
#

#This file is from crashupload repository
#Uploads coredumps to an ftp server if there are any
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

if [ -f /lib/rdk/uploadDumpsUtils.sh ];then
     . /lib/rdk/uploadDumpsUtils.sh
fi

if [ -f /lib/rdk/uploadDumpsUtilsDevice.sh ];then
     . /lib/rdk/uploadDumpsUtilsDevice.sh
fi

if [ "$DEVICE_TYPE" != "mediaclient" ] && [ -f $RDK_PATH/commonUtils.sh ]; then
     . $RDK_PATH/commonUtils.sh
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

# export PATH and LD_LIBRARY_PATH for curl
export PATH=$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# causes a pipeline to produce a failure return code in case of errors
set -o pipefail

if [ "$DEVICE_TYPE" = "broadband" ];then
       CERTFILE="/etc/ssl/certs/ca-certificates.crt"
else
       CERTFILE="/etc/ssl/certs/qt-cacert.pem"
fi
S3BUCKET="ccp-stbcrashes"
HTTP_CODE="/tmp/httpcode"
S3_FILENAME=""

# Yocto conditionals
TLS="--tlsv1.2"

if [ -f /etc/os-release ]; then
    CORE_PATH="/var/lib/systemd/coredump/"
fi

encryptionEnable=false
if [ -f /etc/os-release ]; then
    encryptionEnable=`tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EncryptCloudUpload.Enable 2>&1 > /dev/null`
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

logMessage()
{
    message="$1"
    echo "[PID:$$ `date -u +%Y/%m/%d-%H:%M`]: $message" >> $CORE_LOG
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

if [ "$DUMP_FLAG" = "1" ] ; then
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

sanitize()
{
   toClean="$1"
   # remove all except alphanumerics and some symbols
   # don't use stmh like ${toClean//[^\/a-zA-Z0-9 :+,]/} \
   # here since it doesn't work with slash (due to old busybox version, probably)
   clean=`echo "$toClean"|sed -e 's/[^/a-zA-Z0-9 :+._,=-]//g'`
   echo "$clean"
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
    if [ "$num_of_files" -gt 1 ]; then
        most_recent_file=`find "$path" -type f -exec stat -c "%Y %n" {} + | sort -r | head -n 1 | cut -d' ' -f2`
        most_recent_file=`basename "${most_recent_file}"`
        # Pace X1 does not support "-not" for find, have to use "!" here:
        deleted_files=`find "$path" -type f ! -name "${most_recent_file}" -print -exec rm -f {} \;`
        logMessage "Deleting dump files: ${deleted_files}"
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
       if [ $DUMP_FLAG -eq 1 ];then
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

if [ "$DUMP_FLAG" = "1" ] ; then
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
        WORKING_DIR="/opt/minidumps"
    fi
    DUMPS_EXTN=*.dmp
    TARBALLS=*.dmp.tgz
    CRASH_PORTAL_PATH="/opt/crashportal_uploads/minidumps/"
    #to limit this to only one instance at any time..
    LOCK_DIR_PREFIX="/tmp/.uploadMinidumps"
fi

if [ "$BUILD_TYPE" = "prod" ]; then
    PORTAL_URL="crashportal.ccp.xcal.tv"
elif [ "$BUILD_TYPE" = "vbn" ]; then
    PORTAL_URL="vbn.crashportal.ccp.xcal.tv"
elif [ "$BUILD_TYPE" = "dev" ]; then
    if [ "$DEVICE_TYPE" = "broadband" ];then
        PORTAL_URL="vbn.crashportal.ccp.xcal.tv"
    else
        PORTAL_URL="crashportal.dt.ccp.cable.comcast.com"
    fi
else
    # Lab2 crashportal
    PORTAL_URL="162.150.27.194"
fi

DENY_UPLOADS_FILE="/tmp/.deny_dump_uploads_till"
ON_STARTUP_DUMPS_CLEANED_UP_BASE="/tmp/.on_startup_dumps_cleaned_up"

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
    find "$WORKING_DIR" -name "$DUMPS_EXTN" -type f -o -name "*.tgz" |
      while read file; do
          logMessage "Removing $file because upload limit has been reached"
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
    logMessage "removing $new_tgz_name"
    rm -f $new_tgz_name
}

# Note: This is not protected by the lock below.
TIMESTAMP_FILENAME="/tmp/.${DUMP_NAME}_upload_timestamps"

# Will wait if unable to create lock and 4th parameter is "wait_for_lock".
if [ "$WAIT_FOR_LOCK" = "wait_for_lock" ]; then
    create_lock_or_wait $LOCK_DIR_PREFIX
else
    create_lock_or_exit $LOCK_DIR_PREFIX
fi

if [ "$DEVICE_TYPE" != "broadband" ];then
    # wait the internet connection once after boot
    NETWORK_TEST_ITERATIONS=6
    NETWORK_TEST_DELAY=10
    IPV4_FILE="/tmp/estb_ipv4"
    IPV6_FILE="/tmp/estb_ipv6"
    counter=1

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
                        break
                    fi
                else
                    if [ "Y$estbIp" = "Y$DEFAULT_IP" ]; then
                        logMessage "Waiting the IPv4."
                        sleep $NETWORK_TEST_DELAY
                    else
                        logMessage "Internet is up."
                        break
                    fi
                fi
            fi

            if [ $counter = $NETWORK_TEST_ITERATIONS ]; then
                 logMessage "Continue without IP."
                 break
            fi

            counter=$(( counter + 1 ))
        done
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

x=0
while [ ! -f /tmp/coredump_mutex_release -a $DUMP_FLAG -eq 1 ]; do
     logMessage "Waiting for Coredump Completion"
     sleep 3
     x=`expr $x + 1`
     if [ $x -eq 4 ];then break; fi
done

if [ -f /tmp/set_crash_reboot_flag ];then
      logMessage "Skipping upload, Since Box is Rebooting now"
      logMessage "Upload will happen on next reboot"
      exit 0
fi

# Get the MAC address of the box
MAC=`getMacAddressOnly`
# Ensure MAC is not empty
checkMAC

logMessage "Mac address is $MAC"

count=`find "$WORKING_DIR" -name "$DUMPS_EXTN" -type f | wc -l`
if [ $count -eq 0 ]; then logMessage "No ${DUMP_NAME} for uploading" ; exit 1; fi

cleanup
logMessage "Portal URL: $PORTAL_URL"

uploadToS3()
{
    URLENCODE_STRING=""
    local file=$(basename $1)
    #logMessage "uploadToS3 '$(readlink $1)'"
    logMessage "uploadToS3 $1"
    local app=${file%%.signal*}
    #get signed parameters from server
    local OIFS=$IFS
    IFS=$'\n'
    logMessage "[$0]: S3 Amazon Signing URL: $S3_AMAZON_SIGNING_URL"   
    CurrentVersion=`grep imagename /$VERSION_FILE | cut -d':' -f2`

    IF_OPTION=""
    if [ "$DEVICE_TYPE" = "broadband" ] && [ "$MULTI_CORE" = "yes" ];then
          core_output=`get_core_value`
          if [ "$core_output" = "ARM" ];then 
                IF_OPTION="$ARM_INTERFACE"
          fi
    fi

    if [ "$DEVICE_TYPE" != "broadband" ]; then
        logMessage "RFC_EncryptCloudUpload_Enable:$encryptionEnable"
        if [ "$encryptionEnable" == "true" ]; then
            S3_MD5SUM="$(openssl md5 -binary < $file | openssl enc -base64)"
            URLENCODE_STRING="--data-urlencode \"md5=$S3_MD5SUM\""
        fi
    fi

    if [ ! -z "$IF_OPTION" ]; then
        CURL_CMD="curl -s $TLS --interface $IF_OPTION --cacert "$CERTFILE" -o /tmp/signed_url -w \"%{http_code}\" --data-urlencode "filename=$file"\
                                             --data-urlencode "firmwareVersion=$CurrentVersion"\
                                             --data-urlencode "env=$BUILD_TYPE"\
                                             --data-urlencode "model=$modNum"\
                                             --data-urlencode "type=$DUMP_NAME" \
                                             $URLENCODE_STRING\
                                             "$S3_AMAZON_SIGNING_URL""
    else
        CURL_CMD="curl -s $TLS --cacert "$CERTFILE" -o /tmp/signed_url -w \"%{http_code}\" --data-urlencode "filename=$file"\
                                             --data-urlencode "firmwareVersion=$CurrentVersion"\
                                             --data-urlencode "env=$BUILD_TYPE"\
                                             --data-urlencode "model=$modNum"\
                                             --data-urlencode "type=$DUMP_NAME" \
                                             $URLENCODE_STRING\
                                             "$S3_AMAZON_SIGNING_URL""

    fi
    status=`eval $CURL_CMD > $HTTP_CODE`
    local ec=$?
    IFS=$OIFS
    logMessage "[$0]: Execution Status: $ec, HTTP SIGN URL Response: `cat $HTTP_CODE`"
    if [ $ec -eq 0 ]; then
        if [ -z "$1" ]; then
            ec=1
            logMessage "[$0]: S3 Amazon Signing Request Failed..!"
        else
            #make params shell-safe
            local validDate=`sanitize "$1"`
            local auth=`sanitize "$2"`
            local remotePath=`sanitize "$3"`
            logMessage "Safe params: $validDate -- $auth -- $remotePath"
            tlsMessage="with TLS1.2"
            logMessage "Attempting TLS1.2 connection to Amazon S3"
    	    if [ "$DEVICE_TYPE" = "broadband" ] && [ "$MULTI_CORE" = "yes" ];then
            	core_output=`get_core_value`
            	if [ "$core_output" = "ARM" ];then
		    CURL_CMD="curl -v -fgL --tlsv1.2 --interface $ARM_INTERFACE -T \"$file\" -w \"%{http_code}\" \"`cat /tmp/signed_url`\""
		else
		    CURL_CMD="curl -v -fgL --tlsv1.2 --cacert "$CERTFILE" -T \"$file\" -w \"%{http_code}\" \"`cat /tmp/signed_url`\""
		fi
	    else
                S3_URL=$(cat /tmp/signed_url)
                if [ "$encryptionEnable" != "true" ]; then
                    S3_URL=\"$S3_URL\"
                fi
                CURL_CMD="curl -v -fgL $TLS --cacert "$CERTFILE" -T \"$file\" -w \"%{http_code}\" $S3_URL"
	    fi
            CURL_REMOVE_HEADER=`echo $CURL_CMD | sed "s/-H .*https/https/"`
            logMessage "URL_CMD: $CURL_REMOVE_HEADER"
            result= eval $CURL_CMD > $HTTP_CODE                                  
            ec=$?
            rm /tmp/signed_url
            logMessage "Execution Status:$ec HTTP Response code: `cat $HTTP_CODE` "
         fi
     fi
     if [ $ec -ne 0 ]; then
         logMessage "Curl finished unsuccessfully! Error code: $ec"
     else
        logMessage "S3 ${DUMP_NAME} Upload is successful $tlsMessage"
     fi
    return $ec
}

failOverUploadToCrashPortal()
{
    local coreFile=$1
    local host=$PORTAL_URL
    local remotePath=$CRASH_PORTAL_PATH
    local dirnum=''

    if [ "$DEVICE_TYPE" = "broadband" ];then
        dirnum=`awk -v min=5 -v max=100 'BEGIN{srand(); print int(min+rand()*(max-min+1))}'`
    else
        dirnum=$(( $RANDOM % 100 ))
    fi
    if [ "$dirnum" -ge "0" -a "$dirnum" -le "9" ]; then
        dirnum="0$dirnum"
    fi

    if [ "$DEVICE_TYPE" = "broadband" ] && [ "$MULTI_CORE" = "yes" ];then
             output=`get_core_value`
             if [ "$output" = "ARM" ];then
                   logMessage "Upload string: curl -v $TLS --interface $ARM_INTERFACE --upload-file ./$coreFile https://${host}:8090/upload?filename=$remotePath/$dirnum/$coreFile&user=ccpstbscp"
                   curl -v $TLS --interface $ARM_INTERFACE --upload-file ./$coreFile "https://${host}:8090/upload?filename=$remotePath/$dirnum/$coreFile&user=ccpstbscp"
             else
                   logMessage "Upload string: curl -v $TLS --upload-file ./$coreFile https://${host}:8090/upload?filename=$remotePath/$dirnum/$coreFile&user=ccpstbscp"
                   curl -v $TLS --upload-file ./$coreFile "https://${host}:8090/upload?filename=$remotePath/$dirnum/$coreFile&user=ccpstbscp"
             fi
        else
            logMessage "Upload string: curl -v $TLS --upload-file ./$coreFile https://${host}:8090/upload?filename=$remotePath/$dirnum/$coreFile&user=ccpstbscp"
            curl -v $TLS --upload-file ./$coreFile "https://${host}:8090/upload?filename=$remotePath/$dirnum/$coreFile&user=ccpstbscp"
    fi
    local result=$?
    if [ $result -eq 0 ]; then
        logMessage "Success uploading ${DUMP_NAME} file: $coreFile to $host:$remotePath/$dirnum/."
    else
        logMessage "Uploading ${DUMP_NAME} to the Server failed..."
    fi
    return $result
}

VERSION_FILE="version.txt"
VERSION_FILE_PATH="/${VERSION_FILE}"
boxType=$BOX_TYPE
if [ "$DEVICE_TYPE" = "broadband" ];then
    modNum=`dmcli eRT getv Device.DeviceInfo.ModelName | grep value | cut -d ":" -f 3 | tr -d ' ' `
    if [ ! "$modNum" ];then
        modNum=`cat /etc/device.properties | grep MODEL_NUM | cut -f2 -d=`
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
    OCAPLOG_FILE=$LOG_PATH/ocapri_log.txt
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
else
    if [ "$DUMP_FLAG" != "1" ]; then
    # if the build type is PROD and script is in minidump's mode we should add receiver log and applications.log
        #Receiver Logs
        STBLOG_FILE=/opt/logs/receiver.log
        #applications.log
        APP_LOG=$LOG_PATH/applications.log
        #cef.log
        CEF_LOG=$LOG_PATH/cef.log
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
fi

# use for loop read all nameservers
logFileCopy()
{
    line_count=5000
    if [ "$BUILD_TYPE" = "prod" ]; then
       line_count=500
    fi

    if [ ! -z "$STBLOG_FILE" -a -f "$STBLOG_FILE" ]; then
        tail -n ${line_count} $STBLOG_FILE > $stbLogFile
    fi
    if [ ! -z "$OCAPLOG_FILE" -a -f "$OCAPLOG_FILE" ]; then
        tail -n ${line_count} $OCAPLOG_FILE > $ocapLogFile
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
        tail -n ${line_count} $CEF_LOG > $cefLogFile
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

processDumps()
{
    find -name "$DUMPS_EXTN" -type f | while read f;
    do
        local f1=$(echo "$f" | sed -e 's/[][ :+,=]//g')
        if [ -z "$f1" ]; then
            rm -f "$f"
            continue
        elif [ "$f1" != "$f" ]; then
            mv "$f" "$f1"
            f="$f1"
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
                tgzFile=$dumpName".core.tgz"
            else
                dumpName=`setLogFile $sha1 $MAC $CRASHTS $boxType $modNum $f`
                if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ];then
                    logFileCopy 0
                fi
                tgzFile=$dumpName".tgz"
            fi

            mv $f $dumpName
            cp "/"$VERSION_FILE .

            logMessage "Size of the file: `ls -l $dumpName`"
            if [ "$DUMP_FLAG" == "1" ] ; then
                nice -n 19 tar -zcvf $tgzFile $dumpName $stbLogFile $ocapLogFile $messagesTxtFile $appStatusLogFile $appLogFile $cefLogFile $VERSION_FILE $CORE_LOG 2>&1 | logStdout
                if [ $? -eq 0 ]; then
                    logMessage "Success Compressing the files, $tgzFile $dumpName $stbLogFile $ocapLogFile $messagesTxtFile $appStatusLogFile $appLogFile $cefLogFile $VERSION_FILE $CORE_LOG "
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
            else
                if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ];then
                    nice -n 19 tar -zcvf $tgzFile $dumpName $VERSION_FILE $stbLogFile $ocapLogFile $messagesTxtFile $appStatusLogFile $appLogFile $cefLogFile $CORE_LOG 2>&1 | logStdout
                    if [ $? -eq 0 ]; then
                        logMessage "Success Compressing the files, $tgzFile $dumpName $VERSION_FILE $stbLogFile $ocapLogFile $messagesTxtFile $appStatusLogFile $appLogFile $cefLogFile $CORE_LOG "
                    else
                        logMessage "Compression Failed ."
                    fi
                elif [ "$DEVICE_TYPE" = "broadband" ]; then
                    nice -n 19 tar -zcvf $tgzFile $dumpName $VERSION_FILE $CORE_LOG 2>&1 | logStdout
                    if [ $? -eq 0 ]; then
                        logMessage "Success Compressing the files, $tgzFile $dumpName $VERSION_FILE $CORE_LOG "
                    else
                        logMessage "Compression Failed ."
                    fi
                else
                       echo "$0 New Model, need to add support..!"
                fi
            fi
            logMessage "Size of the compressed file: `ls -l $tgzFile`"

            rm $dumpName
            if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ];then
                if [ ! -z "$STBLOG_FILE" -a -f "$STBLOG_FILE" ]; then
                    logMessage "Removing $stbLogFile"
                    rm $stbLogFile
                fi
                if [ ! -z "$OCAPLOG_FILE" -a -f "$OCAPLOG_FILE" ]; then
                    logMessage "Removing $ocapLogFile"
                    rm $ocapLogFile
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
       fi
    done

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
                     break
                fi
            done
            if [ $status -ne 0 ];then
                  logMessage "[$0]: Fail Over Mechanism: CURL $DUMP_NAME to crashportal"
                  failOverUploadToCrashPortal "$S3_FILENAME"
                  if [ $? -ne 0 ]; then
                        logMessage "[$0]: Fail Over Mechanism for $DUMP_NAME : Failed..!"
			            logMessage "Removing file $S3_FILENAME"
			            rm -f $S3_FILENAME                        
                        exit 1
                  fi
            else
                  echo "[$0]: Execution Status: $status, S3 Amazon Upload of $DUMP_NAME Success"
            fi
            logMessage "Removing file $S3_FILENAME"
            rm -f $S3_FILENAME
            logUploadTimestamp
        fi
    done
    local result=$?

    return $result
}

if [ "$DUMP_FLAG" = "0" ]; then
    processDumps
else
    for i in 1 2 3 4 5; do
        if processDumps; then
            break
        fi
        logMessage "Network error, sleep 30s"
        sleep 30s
    done
fi

finalize
