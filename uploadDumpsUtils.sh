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

CMINTERFACE="wan0"
WANINTERFACE="erouter0"
# Set the name of the log file using SHA1
setLogFile()
{
    fileName=`basename $6`
    echo $1"_mac"$2"_dat"$3"_box"$4"_mod"$5"_"$fileName
}
 
getLastModifiedTimeOfFile()
{
    if [ -f $1 ] ; then
        stat -c '%y' $1 | cut -d '.' -f1 | sed -e 's/[ :]/-/g'
    fi
} 
Timestamp()
{
            date +"%Y-%m-%d %T"
}

# Get the MAC address of the machine
getMacAddressOnly()
{
     mac=`ifconfig $WANINTERFACE | grep HWaddr | cut -d " " -f7 | sed 's/://g'`
     echo $mac
}

# Get the SHA1 checksum
getSHA1()
{
    sha1sum $1 | cut -f1 -d" "

}

# IP address of the machine
getIPAddress()
{
    wanIP=`ifconfig $WANINTERFACE | grep "inet addr" | grep -v inet6 | cut -f2 -d: | cut -f1 -d" "`
    echo $wanIP
}

processCheck()
{
   ps -ef | grep $1 | grep -v grep > /dev/null 2>/dev/null
   if [ $? -ne 0 ]; then
         echo "1"
   else
         echo "0"
   fi
}

getMacAddress()
{
    mac=`ifconfig $CMINTERFACE | grep HWaddr | cut -d " " -f11`
    echo $mac
}

## Get eSTB mac address
getErouterMacAddress()
{
    erouterMac=`ifconfig $WANINTERFACE | grep HWaddr | cut -d " " -f7`
    echo $erouterMac
}

rebootFunc()
{
    #sync
    process=`cat /proc/$PPID/cmdline`
    echo "RebootReason: Rebooting the box.. Trigger from $process" >> /opt/logs/rebootInfo.log
    /rebootNow.sh -s crashUpload_"`basename $0`"
}

# Return system uptime in seconds
Uptime()
{
     cat /proc/uptime | awk '{ split($1,a,".");  print a[1]; }'
}

## Get Model No of the box
getModel()
{
  echo `cat /fss/gw/version.txt | grep ^imagename= | cut -d "=" -f 2 | cut -d "_" -f 1`
}

