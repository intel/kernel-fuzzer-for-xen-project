#!/bin/sh

if test $# -ne 2; then
    printf 'You need to specify the two domain names you want bridged\n' "$@";
    exit 1
fi

id1=$(xl domid "$1")
id2=$(xl domid "$2")
tty1=$(xenstore-read /local/domain/${id1}/serial/0/tty)
tty2=$(xenstore-read /local/domain/${id2}/serial/0/tty)
echo "Bridging TTY1: $tty1 <-> TTY2: $tty2"
socat $tty1,raw $tty2,raw
