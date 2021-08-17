#!/bin/bash
#
# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: MIT
#
# Dump information from Simics checkpoint required to load the
# state up for fuzzing on Xen using KF/x.

if [ $# -ne 2 ]; then
    echo "simics2kfx.sh <path/to/simics> <path/to/checkpoint>"
    exit 1
fi

simics=$1
checkpoint=$2

if [ ! -f $simics ]; then
    echo "Please specify the path to the simics binary"
    exit 1;
fi

if [ ! -d $checkpoint ]; then
    echo "Please specify the Simics checkpoint folder"
    exit 1;
fi

echo "Saving memory"

read -r -d '' simicsinfo << EOM
read-configuration $checkpoint
start-command-line-capture -overwrite simics-regs
pregs -all
stop-command-line-capture
start-command-line-capture -overwrite simics-memmap
memory-map
stop-command-line-capture
quit
EOM

echo "$simicsinfo" > simics-info
$simics -no-gui -no-win -e "run-command-file simics-info" 1>/dev/null 2>&1
rm simics-info

rm memmap 2>/dev/null || :
touch memmap
touch vmcore
fileoffset=0x0
while read p; do
    ram=$(echo -n "$p" | grep ".ram")
    if [ ! -z "$ram" ]; then
        addr=$(echo -n "$ram" | awk -F'│' '{ print $2 }')
        size=$(echo -n "$ram" | awk -F'│' '{ print $3 }')
        size=$(printf '0x%x' "$(($size - $addr + 0x1))")
        echo "$fileoffset $addr $size" >> memmap
        echo "Saving memory from $addr, size $size. File offset: $fileoffset"

        fileoffset=$(printf '0x%x' "$((fileoffset + $size))")

        read -r -d '' simicssave << EOM
read-configuration $checkpoint
save-file mem $addr $size
quit
EOM

        echo "$simicssave" > simics-save
        $simics -no-gui -no-win -e "run-command-file simics-save" 1>/dev/null 2>&1
        cat vmcore mem > tmp
        mv tmp vmcore
        rm mem
        rm simics-save
    fi
done <simics-memmap

echo "Memory saved"
echo "Saving registers"

rm regs.csv 2>/dev/null || :
touch regs.csv

gunzip -d -c $checkpoint/config.gz > simics-config

regs=(rax rbx rcx           \
      rdx rsi rdi           \
      rsp rbp r8            \
      r9 r10 r11            \
      r12 r13 r13           \
      r14 r15 rip           \
      eflags                \
      cr0 cr2 cr3 cr4       \
      dr6 dr7               \
      idtr_base idtr_limit  \
      gdtr_base gdtr_limit  \
      ia32_efer             \
      ia32_star ia32_cstar ia32_lstar \
      ia32_sysenter_cs ia32_sysenter_eip ia32_sysenter_esp \
      ia32_kernel_gs_base   \
      xcr0)

for reg in ${regs[@]}; do
    val=$(cat simics-config | grep -m1 "$reg:" | awk '{ print $2 }')
    echo "$reg,$val" >> regs.csv
done

regs=(cs ds es fs gs ss ldtr tr)
for reg in ${regs[@]}; do
    selector=$(cat simics-regs | grep -m1 "$reg" | tr -d ',' | awk '{ print $3 }')
    base=$(cat simics-regs | grep -m1 "$reg" | tr -d ',' | awk '{ print $6 }')
    limit=$(cat simics-regs | grep -m1 "$reg" | tr -d ',' | awk '{ print $9 }')
    attr=$(cat simics-regs | grep -m1 "$reg" | tr -d ',' | awk '{ print $12 }')

    # The Simics segment attributes are in VT-x representation but shifted right by 8
    # Convert to Xen representation
    attr=$(( $(($attr & 0xff)) | $(( $(($attr & 0xf000)) >> 4)) ))

    echo "$reg,$selector,$base,$limit,$attr" >> regs.csv
done

echo "Registers saved, done!"

rm simics-regs
rm simics-memmap
rm simics-config
