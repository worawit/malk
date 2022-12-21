# malk

When VBS and HVCI are enabled, an unsigned code cannot be loaded into kernel. This project demonstrates another approach to call a kernel function and handle process creation callback when HVCI is enabled.

**Note**: This project is only tested on Windows 11 22H2 on Intel 10th gen.


## Requirements
- Drivers - see [Required Drivers](#required-drivers)
- Windows HVCI is enabled
- Administrative privilege


## Required Drivers

I'm not comfortable redistributing the driver. The program requires following drivers (with sha1 hash) in an executable directory.
- procmon391.sys - 6b95d0e221ea17c59590d94eb9ffdd706f3e1ea6
  - Process Monitor Driver version 3.91 (extracted from Process Monitor version 3.92)
  - Older versions are usable too because they are not compiled with CFG enabled but gadget offsets must be changed
- Dell BIOS driver version 2.7 which contains following files (version 2.5 should work too)
  - DBUtilDrv2.cat - 06f2b629e7303ac1254b52ec0560c34d72b46155
  - dbutildrv2.inf - 19f8da3fe9ddbc067e3715d15aed7a6530732ab5
  - DBUtilDrv2.sys - b03b1996a40bfea72e4584b82f6b845c503a9748
  - WdfCoInstaller01009.dll - c1e821b156dbc3feb8a2db4fdb9cf1f5a8d1be6b


## Usages

The program allows only 2 options.

-dse : the option for setting a callback to CI!CiValidateImageHeader. 0 (default value) means the value will be changed to nt!rand. The effect is same as disable Driver Signature Enforcement.

-cb : the demonstration of process creation callback. The callback does only block notepad.exe and msedge.exe. You have to modify the code to change the callback functionality.


## Limitations

- does not work when Intel Virtualization Technology Redirect Proection (VT-rp) is used. The CPU feature is in Intel 12th gen and later.
- cannot do chained calls.
