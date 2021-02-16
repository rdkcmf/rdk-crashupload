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
     PARTER_ID=`syscfg get PartnerID`
     if [ "$PARTER_ID" = "sky-italia" ] || [ "$PARTER_ID" = "sky-uk" ]; then
         #FEATURE_RDKB_WAN_MANAGER
         wan_if=`syscfg get wan_physical_ifname`
         mac=`cat /sys/class/net/$wan_if/address | tr '[a-f]' '[A-F]' `
     else
         mac=`ifconfig $WANINTERFACE | grep HWaddr | cut -d " " -f7 | sed 's/://g'`
     fi
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
    PARTER_ID=`syscfg get PartnerID`
    if [ "$PARTER_ID" = "sky-italia" ] || [ "$PARTER_ID" = "sky-uk" ]; then
        #FEATURE_RDKB_WAN_MANAGER
        wan_if=`syscfg get wan_physical_ifname`
        erouterMac=`cat /sys/class/net/$wan_if/address | tr '[a-f]' '[A-F]' `
    else
        erouterMac=`ifconfig $WANINTERFACE | grep HWaddr | cut -d " " -f7`
    fi
    echo $erouterMac
}

rebootFunc()
{
    #sync
    if [[ $1 == "" ]] && [[ $2 == "" ]]; then
       process=`cat /proc/$PPID/cmdline`
       reason="Rebooting by calling rebootFunc of utils.sh script..."
    else
       process=$1
       reason=$2
    fi
    /rebootNow.sh -s $process -o $reason
}

# Return system uptime in seconds
Uptime()
{
     cat /proc/uptime | awk '{ split($1,a,".");  print a[1]; }'
}

## Get Model No of the box
getModel()
{
  echo `cat /fss/gw/version.txt | grep ^imagename: | cut -d ":" -f 2 | cut -d "_" -f 1`
}

