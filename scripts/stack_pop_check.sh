#!/bin/bash
# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: MIT
#
# Given a stack backtrace find how far up the stack execution pops within
# a limited number of steps. Stack backtrace is assumed to be bottom-up with
# RIP at the bottom.

domid=$1
limit=$2
stack=$3

if [ -z "$domid" ]; then
    echo "Usage: <domid> <limit> <stacktrace>"
    exit 0;
fi
if [ -z "$limit" ]; then
    echo "Usage: <domid> <limit> <stacktrace>"
        exit 0;
fi
if [ -z "$stack" ]; then
    echo "Usage: <domid> <limit> <stacktrace>"
    exit 0;
fi

forkid=$(forkvm $domid | awk '{ print $4 }')

echo "Fork VM created with id $forkid, singlestepping up to $limit instructions"

stepper --domid $forkid --limit $limit --stop-on-sysret > /tmp/stepper.tmp

xl destroy $forkid > /dev/null 2>&1

lc=$(cat $stack | wc -l)
count=1

while [ $count -le $lc ]
do

    checkaddress=$(sed -n ${count}p $stack | sed -e "s/0x//")

    grep "$checkaddress" /tmp/stepper.tmp > /dev/null

    if [ $? -eq 0 ]; then
        echo "0x$checkaddress"
        break;
    fi

    ((count++))
done

rm /tmp/stepper.tmp
