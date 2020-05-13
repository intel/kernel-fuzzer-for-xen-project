# VMI Kernel Fuzzer for Xen Project*

This project is intended to illustrate the harnessing required to fuzz a Linux kernel module using AFL through the Xen VMI API. The tool utilizes Xen VM forks to perform the fuzzing, thus
allowing for parallel fuzzing/multiple AFL instances to fuzz at the same time. Coverage guidance for AFL is achieved using Capstone to dynamically disassemble the target code to locate
the next control-flow instruction. The instruction is breakpointed and when the breakpoint triggers, MTF is activated to advance the VM ahead, then the processes is repeated again. The
tool allows fine-tuning how many control-flow instructions to allow the fuzzing to encounter before terminating. This provides an alternative to timing out the fuzzing process.

This project is licensed under the terms of the MIT license

# Demo

![](demo.gif)

# Table of Contents
1. [Install dependencies](#section-1)
2. [Grab the project and all submodules](#section-2)
3. [Compile & Install Xen](#section-3)
3.b [Install & Boot Xen from UEFI](#section-3b)
4. [Create VM disk image](#section-4)
5. [Setup networking](#section-5)
6. [Create VM](#section-6)
7. [Grab the kernel's debug symbols & headers](#section-7)
8. [Configure the VM's console](#section-8)
9. [Build the kernel's debug JSON profile](#section-9)
10. [Compile & install LibVMI](#section-10)
11. [Compile kernel-fuzzer](#section-11)
12. [Patch AFL](#section-12)
13. [Add harness](#section-13)
14. [Setup the VM for fuzzing](#section-14)
15. [Connect to the VM's console](#section-15)
16. [Insert the target kernel module](#section-16)
17. [Star fuzzing using AFL](#section-17)
18. [Debugging](#section-18)

# Setup instruction for Debian/Ubuntu:

# 1. Install dependencies <a name="section-1"></a>
----------------------------------
```
sudo apt install git build-essential libfdt-dev libpixman-1-dev libssl-dev libsdl1.2-dev autoconf libtool xtightvncviewer tightvncserver x11vnc libsdl1.2-dev uuid-runtime uuid-dev bridge-utils python3-dev liblzma-dev libc6-dev wget git bcc bin86 gawk iproute2 libcurl4-openssl-dev bzip2 libpci-dev libc6-dev libc6-dev-i386 linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev libssl-dev libsdl-dev iasl libbz2-dev e2fslibs-dev ocaml libx11-dev bison flex ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-pip gcc-7 libcapstone-dev
```

# 2. Grab the project and all submodules <a name="section-2"></a>
----------------------------------
```
git clone https://github.com/intel/kernel-fuzzer-for-xen-project
cd kernel-fuzzer-for-xen-project
git submodule update --init
```

# 3. Compile & Install Xen <a name="section-3"></a>
----------------------------------
There had been some compiler issues with newer gcc's so set your gcc version to GCC-7:

```
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 7
```

Make sure the pci include folder exists at `/usr/include/pci`. In case it doesn't create a symbolic link to where it's installed at:
```
sudo ln -s /usr/include/x86_64-linux-gnu/pci /usr/include/pci
```

Now we can compile Xen
```
cd xen
echo XEN_CONFIG_EXPERT=y > .config
echo CONFIG_MEM_SHARING=y > xen/.config
./configure --disable-pvshim --enable-githttp
make -C xen olddefconfig
make -j4 dist-xen
make -j4 dist-tools
sudo su
make -j4 install-xen
make -j4 install-tools
echo "/usr/local/lib" > /etc/ld.so.conf.d/xen.conf
ldconfig
echo "none /proc/xen xenfs defaults,nofail 0 0" >> /etc/fstab
systemctl enable xen-qemu-dom0-disk-backend.service
systemctl enable xen-init-dom0.service
systemctl enable xenconsoled.service
echo "GRUB_CMDLINE_XEN_DEFAULT=\"console=vga hap_1gb=false hap_2mb=false\""
update-grub
reboot
```

Make sure to pick the Xen entry in GRUB when booting. You can verify you booted into Xen correctly by running `xen-detect`.

## 3.b Booting from UEFI

If Xen doesn't boot from GRUB you can try to boot it from UEFI directly <a name="section-3b"></a>

```
mkdir -p /boot/efi/EFI/xen
cp /usr/lib/efi/xen.efi /boot/efi/EFI/xen
cp /boot/vmlinuz /boot/efi/EFI/xen
cp /boot/initrd.img /boot/efi/EFI/xen
```

Gather your kernel boot command line from /proc/cmdline & paste the following into /boot/efi/EFI/xen/xen.cfg:

```
[global]
default=xen

[xen]
options=console=vga hap_1gb=false hap_2mb=false
kernel=vmlinuz console=hvc0 earlyprintk=xen <YOUR KERNEL'S BOOT COMMAND LINE>
ramdisk=initrd.img
```

Create an EFI boot entry for it:

```
efibootmgr -c -d /dev/sda -p 1 -w -L "Xen" -l "\EFI\xen\xen.efi"
reboot
```

# 4. Create VM disk image <a name="section-4"></a>
----------------------------------
20GB is usually sufficient but if you are planning to compile the kernel from source you will want to increase that.
```
dd if=/dev/zero of=vmdisk.img bs=1G count=20 
```   

# 5. Setup networking <a name="section-5"></a>
----------------------------------
```
sudo brctl addbr xenbr0
sudo ifconfig xenbr0 10.0.0.1 netmask 255.255.255.0 up
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

You might also want to save this as a script or add it to [/etc/rc.local](https://www.linuxbabe.com/linux-server/how-to-enable-etcrc-local-with-systemd)

# 6. Create VM <a name="section-6"></a>
----------------------------------
Paste the following as your domain config, for example into `debian.cfg`, tune it as you see fit. It's important the VM has only a single vCPU.

```
name="debian"
builder="hvm"
vcpus=1
maxvcpus=1
memory=2048
maxmem=2048
hap=1
boot="cd"
serial="pty"
vif=['bridge=xenbr0']
vnc=1
vnclisten="0.0.0.0"
vncpasswd='1234567'
usb=1
usbdevice=['tablet']
# Make sure to update the paths below!
disk=['file:/path/to/vmdisk.img,xvda,w',
      'file:/path/to/debian.iso,xvdc:cdrom,r']
```

Start the VM with:

```
sudo xl create -V debian.cfg
```

Follow the installation instructions in the VNC session. Configure the network manually to 10.0.0.2 with a default route via 10.0.0.1

# 7. Grab the kernel's debug symbols & headers <a name="section-7"></a>
----------------------------------
On Debian systems you can install everything right away

```
sudo apt update && sudo apt install linux-image-$(uname -r)-dbg linux-headers-$(uname-r)
```

On Ubuntu to install the Kernel debug symbols please follow the following tutorial: [https://wiki.ubuntu.com/Debug%20Symbol%20Packages](https://wiki.ubuntu.com/Debug%20Symbol%20Packages)

From the VM copy `/usr/lib/debug/boot/vmlinux-$(uname -r)` and `/boot/System.map-$(uname -r)` to your dom0, for example using scp.

# 8. Configure the VM's console <a name="section-8"></a>
---------------------------------
Edit `/etc/default/grub` and add `console=ttyS0` to `GRUB_CMDLINE_LINUX_DEFAULT` line. Run `sudo update-grub` afterwards.

# 9. Build the kernel's debug JSON profile <a name="section-9"></a>
---------------------------------
Change the paths to match your setup

```
cd dwarf2json
go build
./dwarf2json linux --elf /path/to/vmlinux --system-map /path/to/System.map > ~/debian.json
cd ..
```

# 10. Compile & install LibVMI <a name="section-10"></a>
---------------------------------
```
cd libvmi
autoreconf -vif
./configure --disable-kvm --disable-bareflank --disable-file
make -j4
sudo make install
cd ..
```

Test that base VMI works with:
```
sudo vmi-process-list --name debian --json ~/debian.json
```

# 11. Compile kernel-fuzzer <a name="section-11"></a>
---------------------------------
```
autoreconf -vif
./configure
make -j4
```

# 12. Patch AFL <a name="section-12"></a>
---------------------------------
```
cd AFL
patch -p1 < ../patches/0001-AFL-Xen-mode.patch
make
cd ..
```

# 13. Add harness to target kernel module or function <a name="section-13"></a>
---------------------------------
The target kernel module needs to be harnessed using two CPUID instructions with leaf 0x13371337.
See the `testmodule` folder for an example.

```
static inline void harness(void)
{
    asm (
        "push %rax\n\t"
        "push %rbx\n\t"
        "push %rcx\n\t"
        "push %rdx\n\t"
        "movq $0x13371337,%rax\n\t"
        "cpuid\n\t"
        "pop %rdx\n\t"
        "pop %rcx\n\t"
        "pop %rbx\n\t"
        "pop %rax\n\t"
    );
}
```

You can insert the harness before and after the code segment you want to fuzz:

```
    harness();
    x = test((int)test1[0]);
    harness();
```

# 14. Setup the VM for fuzzing <a name="section-14"></a>
---------------------------------
Start `./kernel-fuzzer`  with the `--setup` option specified. This will wait for the domain to issue the harness CPUID and will leave the domain paused. This ensures that the VM is at the starting location of the code we want to fuzz when we fork it.

```
sudo ./kernel-fuzzer --domain debian --json ~/debian.json --setup
```

You may optionally want to do this in a `screen` session, or you will need a separate shell to continue.

# 15. Connect to the VM's console <a name="section-15"></a>
---------------------------------
```
sudo xl console debian
```

You should see a login screen when you press enter. Proceed to login.

# 16. Insert the target kernel module <a name="section-16"></a>
---------------------------------
```
sudo insmod testmodule.ko
```

The VM's console should now appear frozen. This is normal and what's expected. You can exit the console with `CTRL+]`. The `kernel-fuzzer` should have now also exited with a message `Parent ready`.

# 17. Start fuzzing using AFL <a name="section-17"></a>
---------------------------------
Everything is now ready for fuzzing to begin. The kernel fuzzer takes the input with `--input` flag and the target memory address to write it to via `--address`. With AFL the input file path needs to be `@@`. You also have to first seed your fuzzer with an input that doesn't produces a crash in the code segment being fuzzed.

```
mkdir input
mkdir output
echo -n "not_beef" > input/beef
sudo ./AFL/afl-fuzz -i input/ -o output/ -m 500 -X -- ./kernel-fuzzer --domain debian --json ~/debian.json --input @@ --address 0x<KERNEL VIRTUAL ADDRESS TO WRITE INPUT TO>
```

You can also specify the `--limit` option of how many control-flow instructions you want to encounter before timing out the fuzz iteration. This is an alternative to the AFL built-in time-out model.

The speed of the fuzzer will vary based on how much code you are fuzzing. The more code you are exercising the fewer iterations per second you will see. The testmodule included with the project has been observed to produce a speed of 200-600 iterations per second on i5 family CPUs. Don't forget: you can run multiple instances of the fuzzer to speed things up even further by utilizing more CPU cores on your machine.

After you are finished with fuzzing, the VM can be unpaused and should resume normally without any side-effects.

# 18. Debugging <a name="section-18"></a>
---------------------------------
You can run the kernel fuzzer directly to inject an input into a VM fork without AFL, adding the `--debug` option will provide you with a verbose output.

```
sudo ./kernel-fuzzer --domain debian --json ~/debian.json --debug --input /path/to/input/file --address 0x<KERNEL VIRTUAL ADDRESS TO WRITE INPUT TO>
```


---------------------------------
*Other names and brands may be claimed as the property of others
