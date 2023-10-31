# KF/x - Kernel Fuzzer for Xen Project

Hypervisor-based fuzzing using Xen and AFL. The tool utilizes Xen VM forks to perform the fuzzing, thus
allowing for parallel fuzzing/multiple AFL instances to fuzz at the same time. Coverage guidance for 
AFL is achieved using Intel&reg; Processor Trace or breakpoints.

Minimum hardware requirements: Intel CPU with VT-x and EPT enabled.

This project is licensed under the terms of the MIT license

# Presentations
[![LSS2021](https://img.youtube.com/vi/m_dH59lrj5M/0.jpg)](https://www.youtube.com/watch?v=m_dH59lrj5M)
[![OSSummit2020](https://img.youtube.com/vi/3MYo8ctD_aU/0.jpg)](https://www.youtube.com/watch?v=3MYo8ctD_aU)
[![DEFCON29](https://img.youtube.com/vi/_dXC_I2ybr4/0.jpg)](https://www.youtube.com/watch?v=_dXC_I2ybr4)

# Capability & Limitations

Using this tool you can fuzz both ring-0 (kernel-mode) and ring-3 (user-mode) code, including transition from one to the other using system calls.

Using VM forks for fuzzing on Xen restricts you to fuzz only code that does not perform any I/O operation. This means for example that the target code can't fetch data from disk or communicate over the network. All code and data used for running your target needs to be already in memory when fuzzing begins. Interrupts are blocked during fuzzing so code that relies on timers is also out-of-scope. Furthermore, fuzzing is currently limited to a single vCPU so you won't be able detect race-conditions.

Fuzzing memory that is located on DMA pages is possible but output written to DMA pages will never reach the device. Fuzzing addresses that are designated MMIO areas is not possible. However, if an input is read from MMIO and stored in the VM's normal memory, then that memory can be fuzzed if the harness is placed just after the MMIO read. During fuzzing writes to MMIO memory are discarded.

# Contributions

PRs that are fixing bugs of any kind are welcome but this repository is intended to be only a reference you use to create your own fuzzing setups. We encourage you to fork it and tune it to suite your fuzzing needs. PRs to this repository that add extra features will be kept to a minimum as we try to keep this code-base simple.

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
10. [Compile & install Capstone](#section-10)
11. [Compile & install LibVMI](#section-11)
12. [Compile kfx](#section-12)
13. [Patch AFL](#section-13)
14. [Add harness](#section-14)
15. [Setup the VM for fuzzing](#section-15)
16. [Connect to the VM's console](#section-16)
17. [Insert the target kernel module](#section-17)
18. [Start fuzzing using AFL](#section-18)
19. [Debugging](#section-19)
20. [Intel Processor Trace](#section-20)
21. [Triaging crashes](#section-21)
22. [Advanced harnessing](#section-22)
23. [Coverage info](#section-23)
24. [FAQ](#section-24)

# Setup instruction for Ubuntu:

The following instructions have been mainly tested on Debian Bullseye and Ubuntu 20.04. The actual package names may vary on different distros/versions. You may also find [https://wiki.xenproject.org/wiki/Compiling_Xen_From_Source](https://wiki.xenproject.org/wiki/Compiling_Xen_From_Source) helpful if you run into issues.

# 1. Install dependencies <a name="section-1"></a>
----------------------------------
```
sudo apt-get install git build-essential libfdt-dev libpixman-1-dev libssl-dev libsdl1.2-dev autoconf libtool xtightvncviewer tightvncserver x11vnc uuid-runtime uuid-dev bridge-utils python3-dev liblzma-dev libc6-dev wget git bcc bin86 gawk iproute2 libcurl4-openssl-dev bzip2 libpci-dev libc6-dev libc6-dev-i386 linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev libssl-dev libsdl-dev iasl libbz2-dev e2fslibs-dev ocaml libx11-dev bison flex ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-pip libsystemd-dev cmake snap gcc-multilib nasm binutils bc libunwind-dev ninja-build
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
Make sure the pci include folder exists at `/usr/include/pci`. In case it doesn't create a symbolic link to where it's installed at:
```
sudo ln -s /usr/include/x86_64-linux-gnu/pci /usr/include/pci
```

Before installing Xen from source make sure you don't have any pre-existing Xen packages installed:
```
sudo apt-get remove xen-* libxen*
```

Now we can compile & install Xen
```
cd xen
echo CONFIG_EXPERT=y > xen/.config
echo CONFIG_MEM_SHARING=y >> xen/.config
./configure --disable-pvshim --enable-githttp --enable-ovmf
make -C xen olddefconfig
make -j4 dist-xen
make -j4 dist-tools
su -
make -j4 install-xen
make -j4 install-tools
echo "/usr/local/lib" > /etc/ld.so.conf.d/xen.conf
ldconfig
echo "none /proc/xen xenfs defaults,nofail 0 0" >> /etc/fstab
systemctl enable xencommons.service
systemctl enable xen-qemu-dom0-disk-backend.service
systemctl enable xen-init-dom0.service
systemctl enable xenconsoled.service
echo "GRUB_CMDLINE_XEN_DEFAULT=\"hap_1gb=false hap_2mb=false dom0_mem=6096M hpet=legacy-replacement iommu=no-sharept\"" >> /etc/default/grub
update-grub
reboot
```

Make sure to pick the Xen entry in GRUB when booting. You can verify you booted into Xen correctly by running `xen-detect`.

Note that we assign 6GB RAM to dom0 above which is a safe default but feel free to increase that if your system has a lot of RAM available.

## 3.b Booting from UEFI

If Xen doesn't boot from GRUB you can try to boot it from UEFI directly <a name="section-3b"></a>

```
su -
mkdir -p /boot/efi/EFI/xen
cp /usr/lib64/efi/xen.efi /boot/efi/EFI/xen
cp /boot/vmlinuz /boot/efi/EFI/xen
cp /boot/initrd.img /boot/efi/EFI/xen
```

Gather your kernel boot command line's relevant bits from /proc/cmdline. Copy & paste the following into /boot/efi/EFI/xen/xen.cfg:

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

You may want to use the `-C` option above instead of `-c` if you are on a remote system so you can set only the next-boot to try Xen. This is helpful in case the system can't boot Xen and you don't have remote KVM to avoid losing access in case Xen can't boot for some reason. Use `efibootmgr --bootnext <BOOT NUMBER FOR XEN>` to try boot Xen only on the next reboot.

# 4. Create VM disk image <a name="section-4"></a>
----------------------------------
20GB is usually sufficient but if you are planning to compile the kernel from source you will want to increase that.
```
dd if=/dev/zero of=vmdisk.img bs=1G count=20 
```   

# 5. Setup networking <a name="section-5"></a>
----------------------------------

You can follow [this tutorial to setup dnsmasq](https://computingforgeeks.com/install-and-configure-dnsmasq-on-ubuntu) to provide DHCP to your VMs.

Alternatively, you can configure a static networking as follows:

Create a network bridge using NetPlan at /etc/netplan/02-xenbr0.yaml:
```
network:
  version: 2
  renderer: networkd
  bridges:
    xenbr0:
      dhcp4: no
      addresses: [ 10.0.0.1/24 ]
```

Apply the NetPlan configuration:
```
su -
netplan generate
netplan apply
```

Enable IP forwarding:
```
su -
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl --system
```

Enable NAT and save the iptables rule, make sure to change eth0 to match your interface name facing the internet:
```
su -
iptables -A FORWARD -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
apt-get install iptables-persistent
```

# 6. Create VM <a name="section-6"></a>
----------------------------------
Create the domain configuration file by pasting the following, for example into `debian.cfg`, then tune it as you see fit. It's important the VM has only a single vCPU.

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
vga="stdvga"
nomigrate=1
# Make sure to update the paths below!
disk=['file:/path/to/vmdisk.img,xvda,w',
      'file:/path/to/debian.iso,xvdc:cdrom,r']
```

Start the VM with:

```
sudo xl create debian.cfg
```

You can connect to the VNC session using your favorite VNC viewer or by simply running:

```
vncviewer localhost
```

In case it's a remote system replace localhost with the IP of the system; note however that the VNC connection is not encrypted so it may be better to setup an SSH tunnel to connect through.

Follow the installation instructions in the VNC session. If you use static networking then configure the IP manually to 10.0.0.2/24 with a default route via 10.0.0.1, and choose a DNS server of your own choosing (for example 9.9.9.9).

# 7. Grab the kernel's debug symbols & headers <a name="section-7"></a>
----------------------------------
Inside the VM, using Debian, you can install everything right away

```
su -
apt-get update && apt-get install linux-image-$(uname -r)-dbg linux-headers-$(uname -r)
```

On Ubuntu to install the Kernel debug symbols please follow the following tutorial: [https://wiki.ubuntu.com/Debug%20Symbol%20Packages](https://wiki.ubuntu.com/Debug%20Symbol%20Packages)

From the VM copy `/usr/lib/debug/boot/vmlinux-$(uname -r)` and `/boot/System.map-$(uname -r)` to your dom0, for example using scp.

# 8. Configure the VM's console <a name="section-8"></a>
---------------------------------
Inside the VM, edit `/etc/default/grub` and add `console=ttyS0 nokaslr nopti` to `GRUB_CMDLINE_LINUX_DEFAULT` line. Run `update-grub` afterwards and `reboot`. Note that adding `nokaslr` and `nopti` are optional but can make triaging crashes easier.

# 9. Build the kernel's debug JSON profile <a name="section-9"></a>
---------------------------------
Back in dom0, we'll convert the dwarf debug information to json that we copied in Step 7.  We'll need Go 1.13 or newer for this. You can install it using snap as follows:

```
sudo snap install --classic go
```

If you distro's repository has go 1.13 or newer you can also install it from there (package name is golang-go).

Now we can build dwarf2json and generate the JSON profile. Change the paths to match your setup and make sure your dom0 has enough RAM as this may take up a lot of it.

```
cd dwarf2json
go build
./dwarf2json linux --elf /path/to/vmlinux --system-map /path/to/System.map > ~/debian.json
cd ..
```

# 10. Compile & install Capstone <a name="section-10"></a>
---------------------------------
We use a more recent version from the submodule (4.0.2) then what most distros ship by default. If your distro ships a newer version you could also just install `libcapstone-dev`.

```
cd capstone
mkdir build
cd build
cmake ..
make
sudo make install
sudo ldconfig
cd ../..
```

# 11. Compile & install LibVMI <a name="section-11"></a>
---------------------------------
```
cd libvmi
autoreconf -vif
./configure --disable-kvm --disable-bareflank --disable-file
make -j4
sudo make install
sudo ldconfig
cd ..
```

Test that base VMI works with:
```
sudo vmi-process-list --name debian --json ~/debian.json
```

# 12. Compile kfx <a name="section-12"></a>
---------------------------------
```
autoreconf -vif
./configure
make -j4
```

# 13. Setup AFL <a name="section-13"></a>
---------------------------------

By default you should use AFL++ from [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus). No custom patches are necessary but you need to set an environment variable to ensure fork VMs are cleaned up when AFL++ exits:
```
git clone https://github.com/aflplusplus/aflplusplus
cd aflplusplus
make
sudo make install
export AFL_KILL_SIGNAL=15
```

If you decide to use plain AFL you need to patch it with the KF/x provided patch as such:
```
cd AFL
patch -p1 < ../patches/0001-AFL-Xen-mode.patch
make
sudo make install
cd ..
```

# 14. Add harness to target kernel module or function <a name="section-14"></a>
---------------------------------
The target kernel module needs to be harnessed using two CPUID instructions with leaf 0x13371337.
See the `testmodule` folder for an example.

```
static inline void harness(void)
{
    unsigned int tmp;

    asm volatile ("cpuid"
                  : "=a" (tmp)
                  : "a" (0x13371337)
                  : "bx", "cx", "dx");
}
```

You can insert the harness before and after the code segment you want to fuzz:

```
    harness();
    x = test();
    harness();
```

# 15. Setup the VM for fuzzing <a name="section-15"></a>
---------------------------------
Start `./kfx`  with the `--setup` option specified. This will wait for the domain to issue the harness CPUID and will leave the domain paused. This ensures that the VM is at the starting location of the code we want to fuzz when we fork it. To get the target address and size from the harness, use `-c` option.

```
sudo ./kfx --domain debian --json ~/debian.json --setup -c
```

You may optionally want to do this in a `screen` session, or you will need a separate shell to continue.

# 16. Connect to the VM's console <a name="section-16"></a>
---------------------------------
```
sudo xl console debian
```

You should see a login screen when you press enter. Proceed to login.

# 17. Insert the target kernel module <a name="section-17"></a>
---------------------------------
There is a testmodule included with the repository, you can copy it into the VM and compile it simply by running `make`. Afterwards, load it via:

```
sudo insmod testmodule.ko
```

The VM's console should now appear frozen. This is normal and what's expected. You can exit the console with `CTRL+]`. The `kfx` should have now also exited with a message `Parent ready`.

# 18. Start fuzzing using AFL <a name="section-18"></a>
---------------------------------
Everything is now ready for fuzzing to begin. The kernel fuzzer takes the input with `--input` flag, its size via `--input-limit` and the target memory address to write it to via `--address`. With AFL the input file path needs to be `@@`. You also have to first seed your fuzzer with an input that doesn't produces a crash in the code segment being fuzzed.

```
mkdir input
mkdir output
echo -n "not_beef" > input/beef
```

If you use AFL++:
```
sudo -E afl-fuzz -i input/ -o output/ -- ./kfx --domain debian --json ~/debian.json --input @@ --input-limit 8 --address 0x<KERNEL VIRTUAL ADDRESS TO WRITE INPUT TO>
```

If you use plain AFL:
```
sudo afl-fuzz -i input/ -o output/ -m 1500 -X -- ./kfx --domain debian --json ~/debian.json --input @@ --input-limit 8 --address 0x<KERNEL VIRTUAL ADDRESS TO WRITE INPUT TO>
```

You can also specify the `--limit` option of how many control-flow instructions you want to encounter before timing out the fuzz iteration. This is an alternative to the AFL built-in time-out model.

The speed of the fuzzer will vary based on how much code you are fuzzing. The more code you are exercising the fewer iterations per second you will see. The testmodule included with the project has been observed to produce a speed of 200-600 iterations per second on i5 family CPUs. Don't forget: you can run multiple instances of the fuzzer to speed things up even further by utilizing more CPU cores on your machine.

After you are finished with fuzzing, the VM can be unpaused and should resume normally without any side-effects.

# 19. Debugging <a name="section-19"></a>
---------------------------------
You can run the kernel fuzzer directly to inject an input into a VM fork without AFL, adding the `--debug` option will provide you with a verbose output.

```
sudo ./kfx --domain debian --json ~/debian.json --debug --input /path/to/input/file --input-limit <MAX SIZE TO WRITE> --address 0x<KERNEL VIRTUAL ADDRESS TO WRITE INPUT TO>
```

# 20. Intel Processor Trace <a name="section-20"></a>
---------------------------------
Using Intel Processor Trace to collect the coverage trace information can significantly boost your fuzzing speed. You can check whether your processor supports this feature by running `xl info` and checking whether `vmtrace` is present in the line starting with `virt_caps`. If it's missing, your processor doesn't support this mode.


For this mode to activate you also have to add the following line to your VM's config before you start it:
```
vmtrace_buf_kb=65536
```

**Make sure your dom0 Linux kernel is a recent one. For example linux-image-5.10.0-1019-oem in the Ubuntu 20.04 repository has been confirmed to work. Linux 5.11 or newer will also work.**

When the VM is booted with this option set you can activate Intel PT decoding using the kfx option `--ptcov`. You can adjust the buffer size up to 4GB in case you are fuzzing large code-segments. Beware that each fork will get an individual PT buffer allocated for it, so keep in mind the total memory limit your system has.

Using this coverage tracing mode is more restrictive then the default. You can only fuzz code when the address space doesn't change (ie. no user-to-kernel switch, no process-switch). You also need Xen to run in bare-metal mode, it's not supported in a nested environment.

# 21. Triaging crashes <a name="section-21"></a>
---------------------------------
After AFL finds a crash the first thing to do is to verify that the crash is reproducible. You can use `kfx` to run your target with the crashing input recorded by AFL as this:

```
kfx --domain ubuntu-20.04 --json 5.4.0.json --address 0xffff8880334652b0 --input output/crashes/id\:000000\,sig\:06\,src\:000008\,op\:int16\,pos\:13\,val\:+128 --input-limit 16 --keep --debug
```

With the `--debug` flag specified you will see a verbose output of kfx and you will be able to see which sink point the input reaches. The `--keep` option will leave the VM forks paused after kfx exits, so you can examine the callstack using GDB:

## Online debugging

```
gdbsx -a <vm fork domid> 64 4567 &
gdb vmlinux -ex 'target remote :4567'
```

The `vmlinux` file should be your target kernel's debug file. In the GDB session you can take a look at the stack-trace of the execution by running `backtrace`. To access more advanced kernel debugging features of GDB (the `lx-` commands) it may be necessary to build your target kernel from source and run the gdb command from the kernel source folder.

If you are debugging a loadable kernel module that's in the Linux kernel source tree you will need to load the symbols for it using `lx-symbols`. If you are debugging a module that's out of tree you will manually have to add the symbols while specifying the base-address of where the module is loaded at:

```
lx-lsmod
add-symbol-file </path/to/module.ko> <module base address>
```

Alternatively, you can get full single-step coverage leading up the sink point using the `forkvm`, `rwmem` and `stepper` tools that accompany `kfx`.

```
forkvm <parent domid>
rwmem --domid <vm fork domid> --write 0xffff8880334652b0 --file output/crashes/id\:000000\,sig\:06\,src\:000008\,op\:int16\,pos\:13\,val\:+128 --limit 16
stepper --domid <vm fork domid> --limit 100000 --stop-on-address <sink address> > stepper.log
cat stepper.log | awk '{ print $2 }' | addr2line -e vmlinux -f -p
```

In the above snipped we manually created a fork VM from the parent and then wrote the crash-causing input into the target buffer. These are exactly the steps kfx performs when it performs fuzzing as well. The stepper tool enable singlestepping of the entire VM and runs until `limit` number of instructions have been executed or the CPU reaches an instruction specified in `stop-on-address`. Here you want to specify the sink's address that you know will be reached by this execution from the above step when we ran `kfx` with `--debug`. The stepper output simply logs each instructions that was executed, so we store that log in a file. As the last step, we just look up each address in the kernel's debug image using `addr2line` the get the exact function name and source line that was executed. This is often more accurate to pinpoint the crashing code-site then a stack backtrace would be.

## Offline debugging

You can use the included `capture-vmcore` tool to capture a `vmcore` from the forked VM. Some prerequisites for this to work:

* An arbitrary kdump kernel must be loaded prior to running kfx. This can be done by adding a `crashkernel=128M` to the kernel cmdline and running `kexec -a -p /boot/vmlinux --reuse-cmdline` from userspace.
* The sink point must (forcibly) result in a kernel crash. I.e unpausing the VM at the sink point should result in a kdump kexec attempt.

Capture, compress, and analyze the vmcore using:

```
capture-vmcore --domid <vm fork domid> --json 5.4.0.json --out /tmp/vmcore
makedumpfile -c -d 31 /tmp/vmcore -x vmlinux /tmp/dumpfile
crash vmlinux /tmp/dumpfile 
```

# 22. Advanced harnessing <a name="section-22"></a>
---------------------------------
In case you want to add more then one harness to your target code, you can use the extended harness type as your start harness:

```
static inline void harness_extended(unsigned int magic, void *a, size_t s)
{
    asm volatile ("cpuid"
                  : "=a" (magic), "=c" (magic), "=S" (magic)
                  : "a" (magic), "c" (s), "S" (a)
                  : "bx", "dx");
}

```

This allows you to use any CPUID as your start marker so you can differentiate between them when running `--setup` with the `--magic-mark <magic>` option. For the end harness you will still have to use `0x13371337` as the magic CPUID.

To also transfer extra information about the target memory and size, during the `--setup` step add `-c` so that kfx will know that extra information is transfered via the CPUID instruction. This also eliminates the need for adding any `printk`s the your target and copying it from the console. The reason why we use RSI ("S") above instead of RBX or RDX is because Xen clobbers the registers used by CPUID before we have a chance to see them (only the lower 32-bits of RAX and RCX will be visible to kfx). Feel free to place extra information into other general purpose registers as needed, you will be able to examine them by running `xen-hvmctx <domainid>`.

Subsequently, you can avoid having to pass the input address and limit to the fuzzing step by again using `-c`. This will retrieve harness information that was stashed to VM CPU registers by the setup phase. Note that both conditions are necessary - using an extended harness in code AND running the setup step with `-c`.

You can also use software breakpoints (0xCC) as your harness which can be placed by standard debuggers like GDB. Use `--harness-type breakpoint` for this mode, which is particularly useful when you don't have access to the target's source-code to compile it with the CPUID-based harness. You will need to determine the start byte of the harness that was overwritten by the breakpoint and specify that to kfx with `--start-byte <byte>`. 

# 23. Coverage info <a name="section-23"></a>
---------------------------------
Often times it is necessary to understand what code the fuzzer is exercising and discovers in order to find additional sink points of interest. By specifying `--record-codecov <filename>` on the KF/x command-line it will keep track of all instruction pointers that were discovered across all fuzzing iterations. By issuing signal 10 (`kill -10 <pid>`) to the KF/x process this information will be saved into a the filename specified. The same information is also saved when the KF/x process exits.

# 24. FAQ <a name="section-24"></a>
---------------------------------

> Can I run this on ring3 applications?

You likely get better performance if you run AFL natively on a ring3 application but nothing prevents you from running it via this tool. You would need to adjust the sink points in `src/sink.h` to catch the crash handlers that are called for ring3 apps. For example `do_trap_error` in Linux handles segfaults, you would probably want to catch that.

> Can I fuzz Windows?

This tool currently only targets Linux. You can modify the harness to target Windows or any other operating system by adjusting the sink points in `src/sink.h` that are used to catch a crash condition. You could also manually define the sink points' addresses in case the operating system is not supported by LibVMI. In case you want to fuzz closed-source portions of Windows where you can't inject the `cpuid`-based harness, you can use `--harness breakpoint` to switch to using breakpoints as your harness. This allows you to mark the code-region to fuzz with a standard debugger like WinDBG. You will find [additional information in the Wiki](https://github.com/intel/kernel-fuzzer-for-xen-project/wiki/Fuzzing-Windows)

> Can I just pipe /dev/random in as fuzzing input?

Yes! You can use `--loopmode` to simply read input from whatever source you want and pipe it into the VM forks. In this mode coverage trace is disabled so you will see more iterations per second.

> How do I shutdown the VM after I'm done?

You can issue `xl shutdown <domain name>` to initiate shutdown. If there are VM forks active, you need to issue `xl destroy <domain id>` for each fork before shutdown.

> Any tricks to increase performance?

To max out performance you can boot Xen with "dom0_max_vcpus=2 sched=null spec-ctrl=no-xen" which assigns only 2 vCPUs to dom0, disables the scheduler and speculative execution hardening features. You can also add "smt=0" to disable hyper-threading. Make sure your system has enough physical cores to run each vCPU as they get pinned.

> Is it possible to run the tool nested?

Yes, it has been tested running on top of VMware Workstation. In the VMware VM's CPU settings make sure to enable the "Virtualize Intel VT-x/EPT" option. Performance will be lower as compared to running it directly on the hardware.

---------------------------------
*Other names and brands may be claimed as the property of others
