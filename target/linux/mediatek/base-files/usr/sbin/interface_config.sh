#!/bin/sh

	echo "interface config"
	brctl addbr br-lan
	modprobe /lib/modules/3.10.20/mt7615e.ko
	ifconfig ra0 up
	ifconfig rai0 up
	ifconfig eth0 up
	ifconfig eth1 up
	switch-llllw.sh
	brctl addif br-lan eth0
	brctl addif br-lan rai0
	brctl addif br-lan ra0	
	ifconfig br-lan up
	ifconfig br-lan 192.168.1.1
	ifconfig eth1 192.168.3.1
	
	nat_router_config.sh
	rps_config.sh
	udhcpd -f /etc/udhcpd.config &
