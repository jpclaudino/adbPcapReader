# adbPcapReader
Adb protocol parser. Rebuilds sessions and adb pull/push files from usb packets. 

## Usage
The project aims to reconstruct sessions of the adb protocol from USB traffic captures performed by the USBPcap lib.

The first step consists of capturing USB traffic from interface and save it to a pcap file.
The capture can be performed by Wireshark or directly with the USBPcap lib.

It is recommended that the buffer be specified, as wireshark limits packet sizes to 65Kb.

>
Ex: C:\Program Files\USBPcap>USBPcapCMD.exe --snaplen 10485760 --bufferlen 10485760 --device \\.\USBPcap1 -A -o usbCapture.pcap

After the capture, the python scrypt can be executed:
>
Ex: python adbPcapReader.py "captureFile.pcap"

