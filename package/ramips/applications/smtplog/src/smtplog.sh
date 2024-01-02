#!/bin/sh /etc/rc.common

# Copyright (C) 2015 Mediatek

START=40

sysinfo () {
    [ -f /tmp/sysinfo/model ] && {
            echo -n "device : "
            cat /tmp/sysinfo/model 2>/dev/null
    }
    [ -f /tmp/sysinfo/model ] && {
            echo -n "board : "
            cat /tmp/sysinfo/board_name 2>/dev/null
    }

    echo -n "wan ip : "
    ifconfig eth0.2 | grep "inet addr" | cut -d: -f2 | cut -d" " -f1
    echo -n "kernel : "
    cat /proc/version

    [ -d /etc/wireless ] || return 1
    for dir in /etc/wireless/*
    do
            echo -n `basename $dir`" : "
            [ -f $dir/version ] && {
                    cat "$dir/version"
            }
    done
}


# check if the log contains what we are interested.
checklog() {
    grep -i "kernel panic" /dbg/log/dbg.log > /dev/null
    [ "0" = "$?" ] && {
        echo yes
        return
    }
    grep -i "oops" /dbg/log/dbg.log > /dev/null
    [ "0" = "$?" ] && {
        echo yes
        return
    }
    grep -i "segment fault" /dbg/log/dbg.log > /dev/null
    [ "0" = "$?" ] && {
        echo yes
        return
    }
}


start() {
    [ -f /dbg/log/dbg.log ] || return 1
    # 1. check if the log contains what we are interested.
    match=$( checklog )
    [ "yes" = "$match" ] || return 1
    # 2. backup the log to avoid overwriting.
    cp /dbg/log/dbg.log /dbg/log/dbg.log.bak
    # 3. make sure WAN ready.
    retry=0
    while [ "$myvar" != "2" ]
    do
        ping baidu.com -c 4
        [ "0" = "$?" ] &&  break
        retry=$(( $myvar + 1 ))
        sleep 10
    done
    ping baidu.com -c 2
    [ "0" = "$?" ] || return 1 # give up
    # 4. send the log.
    sysinfo > /tmp/smtplog.sysinfo
    smtplog
}
