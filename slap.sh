#!/bin/bash
# rui@deniable.org
echo -e "\033[1m.: SLAP - Simple Linux Access Point v0.1 :.\033[0m"
echo -e "Assuming \033[1;34meth0\033[0m for external interface and \033[1;34mwlan0\033[0m for wireless interface."
echo "If it's not edit this script manually!"

if [ "$#" -ne 1 ]; then
        echo "Usage: $0 {install|configure|start|stop}"
fi

if [ "$1" = "install" ]; then
	sudo service hostapd stop
	sudo service dnsmasq stop
	sudo update-rc.d hostapd disable
	sudo update-rc.d dnsmasq disable
fi

create_config_files() {
	FILE_DNSMASQ=/etc/dnsmasq.conf
	FILE_HOSTAPD=/etc/hostapd.conf
	if [ $encryption -ne 0 ]; then
		echo -ne "\033[1;32mChoose your passphrase:\033[0m "
		read passphrase
	fi
	sudo echo "bind-interfaces" > $FILE_DNSMASQ 
	sudo echo "interface=wlan0" >> $FILE_DNSMASQ
	sudo echo "dhcp-range=192.168.150.2,192.168.150.253,12h" >> $FILE_DNSMASQ
	sudo echo "# interface" > $FILE_HOSTAPD
	sudo echo "interface=wlan0" >> $FILE_HOSTAPD
	sudo echo "# Select driver" >> $FILE_HOSTAPD
	sudo echo "driver=$1" >> $FILE_HOSTAPD
	sudo echo "# Set access point name" >> $FILE_HOSTAPD
	sudo echo "ssid=$2" >> $FILE_HOSTAPD
	sudo echo "# Set access point harware mode to 802.11g" >> $FILE_HOSTAPD
	sudo echo "hw_mode=g" >> $FILE_HOSTAPD
	sudo echo "# Set WIFI channel (can be easily changed)" >> $FILE_HOSTAPD
	sudo echo "channel=6" >> $FILE_HOSTAPD
	case $encryption in
	1)  sudo echo "wpa=2" >> $FILE_HOSTAPD
		sudo echo "wpa_passphrase=$passphrase" >> $FILE_HOSTAPD
		;;
	2)  sudo echo "wpa=3" >> $FILE_HOSTAPD
		sudo echo "wpa_passphrase=$passphrase" >> $FILE_HOSTAPD
		sudo echo "wpa_key_mgmt=WPA-PSK" >> $FILE_HOSTAPD
		sudo echo "wpa_pairwise=TKIP" >> $FILE_HOSTAPD
		sudo echo "rsn_pairwise=CCMP" >> $FILE_HOSTAPD
		;;
	esac
	exit
}

if [ "$1" = "configure" ]; then
	echo -ne "\033[1;32mEnter your wireless driver \"lspci -k | grep -A 3 -i 'network'\" is your friend:\033[0m "
	read driver
	echo -ne "\033[1;32mEnter your desired SSID:\033[0m "
	read ssid
	while [ 1 ]; do
		echo -ne "\033[1;32mChoose Encryption (0 - No auth; 1 - WPA2; 2 - WPA + WPA2):\033[0m "
		read encryption
		case $encryption in
		0|1|2) create_config_files $driver $ssid $encryption ;;
		*) echo -e "\033[1;32mInvalid option!\033[0m" ;;
		esac
	done
fi

if [ "$1" = "start" ]; then
        # Start
        # Configure IP address for WLAN
        sudo ifconfig wlan0 192.168.150.1
        # Start DHCP/DNS server
        sudo service dnsmasq restart
        # Enable routing
        sudo sysctl net.ipv4.ip_forward=1
        # Enable NAT
        sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        # Run access point daemon
        sudo hostapd /etc/hostapd.conf
fi

if [ "$1" = "stop" ]; then
        # Stop
        # Disable NAT
        sudo iptables -D POSTROUTING -t nat -o eth0 -j MASQUERADE
        # Disable routing
        sudo sysctl net.ipv4.ip_forward=0
        # Disable DHCP/DNS server
        sudo service dnsmasq stop
		sudo service hostapd stop
fi
