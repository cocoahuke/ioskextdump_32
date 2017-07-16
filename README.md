# ioskextdump_32
Dump Kext information from 32bit iOS kernel cache. Applicable to the kernel which dump from memory. The disassembly framework used is [Capstone](http://www.capstone-engine.org/)

[![Contact](https://img.shields.io/badge/contact-@cocoahuke-fbb52b.svg?style=flat)](https://twitter.com/cocoahuke) [![build](https://travis-ci.org/cocoahuke/ioskextdump_32.svg?branch=master)](https://github.com/cocoahuke/ioskextdump_32) [![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cocoahuke/ioskextdump_32/blob/master/LICENSE) [![paypal](https://img.shields.io/badge/Donate-PayPal-039ce0.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=EQDXSYW8Z23UY)

##### 64bit version of iOS:
**64bit(aarch64):  [ioskextdump](https://github.com/cocoahuke/ioskextdump)**
##### 64bit version of iOS10:
**64bit(arm):  [ioskextdump_ios10](https://github.com/cocoahuke/ioskextdump_ios10)**
##### Dump Kext info For Mac:
**64bit(x86_64):  [mackextdump](https://github.com/cocoahuke/mackextdump)**

## This is the arm 32bit version of [ioskextdump](https://github.com/cocoahuke/ioskextdump)

### For kernel which dump from memory
Use [iosdumpkernelfix](https://github.com/cocoahuke/iosdumpkernelfix) to correct the Mach-O header before analyze it, Otherwise The analysis results are not complete list of Kexts

# How to use

**Download**
```bash
git clone https://github.com/cocoahuke/ioskextdump_32.git && cd ioskextdump_32
```
**Compile and install** to /usr/local/bin/

```bash
make
make install
```
**Usage**
```
Usage: ioskextdump_32 [-e] [-p <access directory path>] <kernelcache>
```
`-e` Specify the export mode  
`-p` Specifiy a folder path that contains the data file or export data file to there  
<br>  
**Example to use**
I left a sample iOS9.2 kernelcache in the test directory, try to run this command  
```
ioskextdump_32 -e -p test test/iPhone5_9.2_kernel.arm
```
You will see all Inheritance relationship is empty and `allClass_relation.plist saved success` should be at end of program print  
```
Inheritance relationship:
```
<br>

Then try same command removes `-e`
```
ioskextdump_32 -p test test/iPhone5_9.2_kernel.arm
```
ioskextdump_32 will print contain lists of inheritance and override functions:
```
15.0x80772000 - 0x80799000 com.apple.iokit.IOHIDFamily

total 20 modInit in com.apple.iokit.IOHIDFamily

******** 0:com.apple.iokit.IOHIDFamily *******
(0x80774464)->OSMetaClass:OSMetaClass call 4 args list
r0:0x8078f144
r1:IOHIDLibUserClient
r2:0x80412904
r3:0xc0
vtable start from addr 0x8078a2ec
Inheritance relationship:

0 func:0x80772b51  scalar_i:0x0  struct_i:0x0  scalar_o:0x2  struct_o:0x0
1 func:0x80772b71  scalar_i:0x1  struct_i:0x0  scalar_o:0x0  struct_o:0x0
2 func:0x80772b79  scalar_i:0x0  struct_i:0x0  scalar_o:0x0  struct_o:0x0
...
```
Cannot detect override methods in this program, I was added in [ioskextdump](https://github.com/cocoahuke/ioskextdump program, 32bit device get outdatedness more and more :), anyway 32bit devices are get older and outdatedness :)

Any question just Email me
