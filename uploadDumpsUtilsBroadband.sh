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

if [ -f /lib/rdk/utils.sh ];then
     . /lib/rdk/utils.sh
fi
CMINTERFACE="wan0"
INTERFACE="erouter0"
 
getLastModifiedTimeOfFile()
{
    if [ -f $1 ] ; then
        stat -c '%y' $1 | cut -d '.' -f1 | sed -e 's/[ :]/-/g'
    fi
} 

get_core_value()
{
    core=""
    if [ -f /tmp/cpu_info ];then
         core=`cat /tmp/cpu_info`
    fi
    if [ ! "$core" ];then
           processor=`cat /proc/cpuinfo | grep Atom| wc -l`
           if [ $processor ] && [ $processor -gt 0 ] ;then
                  core="ATOM"
           fi
           processor=`cat /proc/cpuinfo | grep ARM| wc -l`
           if [ $processor ] && [ $processor -gt 0 ] ;then
                  core="ARM"
           fi
           echo $core > /tmp/cpu_info
    fi
    echo $core
}

#Refactor: On Arris XB6 on the ATOM the interface name is ARM_INTERFACE(erouter0)
#          XF3 Doesn't have ATOM or ARM
get_interface_value()
{
   output=""
   if [ -f /tmp/if_info ];then
         output=`cat /tmp/if_info`
   fi
   if [ ! "$output" ];then
         output=`get_core_value`
         case "$output" in
             "ATOM")
                    output=$ATOM_INTERFACE ;;
             "ARM" )
                    output=$ARM_INTERFACE ;;
             *)
                    output="unknown" ;;
         esac
         echo $output > /tmp/if_info
  fi
  echo $output
}

#Refactor: On Arris XB6 on the ATOM the interface name is ARM_INTERFACE(erouter0)
#          XF3 Doesn't have ATOM or ARM
get_mac_address()
{
    INTERFACE=$1
    output=`get_core_value`
    case "$output" in
         "ATOM")
           mac=""
           wanmac_cache="/tmp/.wan_mac"

           if [ ! -f $wanmac_cache ] || [ "`cat $wanmac_cache`" == "" ]; then
               mac=`dmcli eRT getv Device.DeviceInfo.X_COMCAST-COM_WAN_MAC`
               mac=`echo $mac | grep "Execution succeed" | sed 's/.*value://g' | sed 's/ //g;s/://g' | cut -c1-12`
               if [ "$mac" != "" ]; then
                   echo $mac > $wanmac_cache
               fi
           else
               mac=`cat $wanmac_cache`
           fi

           ;;
         "ARM" )
           mac=`ifconfig $ARM_INTERFACE | grep HWaddr | cut -d " " -f7 | sed 's/://g'` ;;
          *)
           mac="00000000";;
    esac
    echo $mac      
}


# Get the MAC address of the machine
getMacAddressOnly()
{
     interface=`get_interface_value`
     if [ "$interface" ];then
           INTERFACE=$interface
     fi
     mac=`get_mac_address "$INTERFACE"`
     echo $mac
}

#Refactor: This Method should really be device specific. This only works for XB3
network_commn_status()
{
    output=`get_core_value`
    case "$output" in
        "ARM")
           INTERFACE=`get_interface_value`
           if [ "$INTERFACE" != "unknown" ];then
             IF_STATE=`sysevent get wan-status`
             EROUTER_IP=`ifconfig $INTERFACE | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
             # Ensure the IP address here
             while [ "$EROUTER_IP" == "" ]; do
                   sleep 5
                   EROUTER_IP=`ifconfig $INTERFACE | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
             done
             # Ensure both IP address and interface status
             while [ "$IF_STATE" != "started" ] && [ "$EROUTER_IP" != "" ];do
                 sleep 5
                 IF_STATE=`sysevent get wan-status`
                 if [ ! "$EROUTER_IP" ];then
                    EROUTER_IP=`ifconfig $INTERFACE | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
                 fi
            done
          fi
          ;;
        "ATOM")
            if [ ! -f /tmp/if_network_status ];then
                 while [ "$status" = "" ] 
                 do
                     output=`dmcli eRT getv Device.DeviceInfo.X_COMCAST-COM_WAN_MAC`
                     status=`echo $output| grep "Execution succeed"`
                     if [ "$status" ];then
                          echo $status > /tmp/if_network_status
                     fi
                 done
            else
                 echo "Network is Ready now..!"
            fi
          ;;
        "*")
          echo "Unknown core value, Not sure about the network config..!"
          ;;
   esac
}
# Get the SHA1 checksum
getSHA1()
{
    sha1sum $1 | cut -f1 -d" "

}


# Return system uptime in seconds
Uptime()
{
     cat /proc/uptime | awk '{ split($1,a,".");  print a[1]; }'
}

get_model_value()
{
    output=`get_core_value`
    case "$output" in
        "ARM")
               #ToDo: fss/gw is XB3 specific shouldn't be here
               model_value=`cat /fss/gw/version.txt | grep ^imagename= | cut -d "=" -f 2 | cut -d "_" -f 1`
               ;;
        "ATOM")
               model_value=`cat /version.txt | grep ^imagename: | cut -d ":" -f 2 | cut -d "_" -f 1`
               ;;
        *)
               model_value="unknown" ;;
    esac
    echo $model_value
}

## Get Model No of the box
getModel()
{
  #ToDo: fss/gw is XB3 specific shouldn't be here
  #This Method will only work for ARM
  echo `cat /fss/gw/version.txt | grep ^imagename= | cut -d "=" -f 2 | cut -d "_" -f 1`
}

