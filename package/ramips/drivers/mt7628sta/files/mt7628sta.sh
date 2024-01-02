#!/bin/sh
append DRIVERS "mt7628sta"

. /lib/wifi/ralink_common.sh
. /lib/wifi/wpa_supplicant.sh

prepare_mt7628sta() {
	logger prepare_mt7628sta
}

scan_mt7628sta() {
	logger scan_mt7628sta
}


disable_mt7628sta() {
	logger disable_mt7628sta
	local ifname
	config_get vifs "$device" vifs
	for vif in $vifs; do
		config_get ifname $vif ifname
		uci -q delete wireless.${vif}.bssid # for luci
		uci -q commit wireless # for luci
		ifconfig $ifname down
	done

	killall wpa_supplicant 2>/dev/null
	echo 0 > /dev/null
}

enable_mt7628sta() {
	logger enable_mt7628sta
	local ifname disabled
	config_get vifs "$device" vifs
	for vif in $vifs; do
		config_get ifname $vif ifname
		config_get disabled $vif disabled
		[ "$disabled" == "1" ] || {
			ifconfig $ifname up
			wpa_supplicant_setup_vif $vif nl80211
		}
	done
}

detect_mt7628sta() {
	cd /sys/module/
	[ -d mt7628sta ] || return
	[ -e /etc/config/wireless ] && return
         cat <<EOF
config wifi-device      mt7628sta
        option type     mt7628sta
        option vendor   ralink
        option ifname   rai0

config wifi-iface
        option device   mt7628sta
        option ifname   rai0
        option mode     sta

EOF
}


