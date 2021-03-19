# adbPcapReader
Adb protocol parser. Rebuilds sessions and adb pull/push files from usb packets.

The script was built by analyzing the adb source code, as the adb documentation made by cstyan.
* [documentation](https://github.com/cstyan/adbDocumentation)
* [protocol](https://android.googlesource.com/platform/packages/modules/adb/+/master/protocol.txt)
* [ADB overview](https://android.googlesource.com/platform/packages/modules/adb/+/master/OVERVIEW.TXT)
* [sync](https://android.googlesource.com/platform/packages/modules/adb/+/master/SYNC.TXT)
* [services](https://android.googlesource.com/platform/packages/modules/adb/+/master/SERVICES.TXT)


## Usage
The project aims to reconstruct sessions of the adb protocol from USB traffic captures performed by the USBPcap lib.
The script can be used as a forensic tool for analyzing android root softwares.

The first step consists of capturing USB traffic from interface and save it to a pcap file.
The capture can be performed by Wireshark or directly with the USBPcap lib.

It is recommended that the buffer be specified, as wireshark limits packet sizes to 65Kb.

> Ex: C:\Program Files\USBPcap>USBPcapCMD.exe --snaplen 10485760 --bufferlen 10485760 --device \\.\USBPcap1 -A -o usbCapture.pcap

After the capture, the python scrypt can be executed:
> Ex: python adbPcapReader.py "captureFile.pcap"

## Output
The script will output two text files (messages and sessions).
The sessions file contains information about file upload/download sessions (adb push an pull), as well as executed shell commands.
The messages file contains all low-level messages sent, such as OPEN, CLSE, WRTE, AUTH, among others.
Two directories are also created. There, all files sent/received via adb push and pull are reassembled.

![output](https://github.com/jpclaudino/adbPcapReader/blob/main/output.PNG)

Messages.txt
> 1.64 -> host: CNXN (Arg 0: 16777216, Arg 1: 262144, Lenght: 7)
  1.64 -> host: AUTH (Arg 0: 1, Arg 1: 0, Lenght: 20)
  1.64 -> host: AUTH (Arg 0: 2, Arg 1: 0, Lenght: 256)
  1.64 -> host: AUTH (Arg 0: 1, Arg 1: 0, Lenght: 20)
  1.64 -> host: AUTH (Arg 0: 2, Arg 1: 0, Lenght: 256)
  1.64 -> host: AUTH (Arg 0: 1, Arg 1: 0, Lenght: 20)
  1.64 -> host: AUTH (Arg 0: 3, Arg 1: 0, Lenght: 717)
  1.64 -> host: CNXN (Arg 0: 16777216, Arg 1: 4096, Lenght: 96)
  1.64 -> host: OPEN (Arg 0: 1044538744, Arg 1: 0, Lenght: 39)
  1.64 -> host: OKAY (Arg 0: 1, Arg 1: 1044538744, Lenght: 0)
  1.64 -> host: WRTE (Arg 0: 1, Arg 1: 1044538744, Lenght: 5)
  1.64 -> host: OKAY (Arg 0: 1044538744, Arg 1: 1, Lenght: 0)
  1.64 -> host: CLSE (Arg 0: 1, Arg 1: 1044538744, Lenght: 0)


Sessions.txt
> *************************** SESSION BEGIN ***************************
  1.64 -> host: OPEN (Arg 0: 77, Arg 1: 0, Lenght: 39)
  Payload: shell:getprop ro.build.version.release
  6.0
  *************************** SESSION END ***************************
  *************************** SESSION BEGIN ***************************
  1.56 -> host: OPEN (Arg 0: 88, Arg 5: 0, Lenght: 6)
  Payload: sync:
   adb push /data/local/tmp/file ***** File Transmission *****
  *************************** SESSION END ***************************

