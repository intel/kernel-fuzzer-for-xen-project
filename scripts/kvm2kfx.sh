#!/bin/bash
#
# Dump KVM VM using virsh qemu-monitor-command and record information
#  required to load the VM up for fuzzing on Xen using KF/x.
#
vm=$1

if [ -z $vm ]; then
    echo "Specify VM name"
    exit 1
fi

echo "Saving vmcore for $vm"

virsh qemu-monitor-command $vm --hmp dump-guest-memory /tmp/$vm-vmcore

mv /tmp/$vm-vmcore $PWD

echo "Creating memory map for $vm"

readelf -l $PWD/$vm-vmcore | grep -A1 LOAD | paste - - | tr -s " " | awk '{ print x$2 " " x$3 " " x$5}' > $PWD/$vm-memmap

echo "Calculating register map for $vm"

baseoffs=$(readelf -n $PWD/$vm-vmcore | grep "notes found" | awk '{ print x$7 }')
coresize=$(readelf -n $PWD/$vm-vmcore | grep "CORE" | awk '{ print x$2 }')
qemusize=$(readelf -n $PWD/$vm-vmcore | grep "QEMU" | awk '{ print x$2 }')

# 0x28 is the size of the elf note headers
printf -v finaloffset '%#x' "$((baseoffs + coresize + 0x28))"

echo $finaloffset $qemusize > $PWD/$vm-regmap

echo "Done"
exit 0
