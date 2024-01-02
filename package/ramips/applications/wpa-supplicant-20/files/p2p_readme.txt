wpa_supplicant -Dnl80211 -i rai0 -c /etc/wpa_supplicant.conf -N -Dnl80211 -i p2p0 -c /etc/p2p_dev.conf -puse_p2p_group_interface=1& 
wpa_cli -ip2p0 p2p_group_add freq=2412 &
ifconfig p2p9 192.168.49.1
killall dnsmasq && udhcpd /etc/p2p_dhcpd.conf

#touch android phone
wpa_cli -ip2p9 wps_pbc 0a:7a:4c:7d:57:0b
ping 192.168.49.100 &
