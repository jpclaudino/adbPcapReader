from scapy.all import *
from struct import *
import os
import sys
import random

#
# adb.h
# --- protocol overview and basics ---------------------------------------
#
# The transport layer deals in "messages", which consist of a 24 byte
# header followed (optionally) by a payload.  The header consists of 6
# 32 bit words which are sent across the wire in little endian format.
#
# struct message {
#     unsigned command;       /* command identifier constant      */
#     unsigned arg0;          /* first argument                   */
#     unsigned arg1;          /* second argument                  */
#     unsigned data_length;   /* length of payload (0 is allowed) */
#     unsigned data_crc32;    /* crc32 of data payload            */
#     unsigned magic;         /* command ^ 0xffffffff             */
# };
#
SESSIONS_FILE = "sessions.txt"
MESSAGES_FILE = "messages.txt"
OUTPUTDIR = "/output"
OUTPUTDIR_PUSH = "/output/push"
OUTPUTDIR_PULL = "/output/pull"
MAXBUFFSIZE = 1048603


class Message():
    def __init__(self, packet, packet_reader):
        packetPayload = packet.payload
        self.info = None
        self.packet = packet
        self.busId = packet.bus
        self.deviceAddress = packet.device
        self.direction = packet.fields["info"]
        self.command = packetPayload.raw_packet_cache[0:4]
        self.arg0 = packetPayload.raw_packet_cache[4:8]
        self.arg1 = packetPayload.raw_packet_cache[8:12]
        self.data_length = packetPayload.raw_packet_cache[12:16]
        self.data_crc32 = packetPayload.raw_packet_cache[16:20]
        self.magic = packetPayload.raw_packet_cache[20:24]
        self.payload = None
        if (self.getCommand() == messageType.get("A_OPEN")) or (
                self.getCommand() == messageType.get("A_WRTE")):
            # Payload always sent after two USB packets
            if self.getDataLenght() != 0:
                self.setPayload(packet_reader)

    def getArg0(self):
        return self.arg0

    def getIntArg0(self):
        tArg0 = unpack('<I', self.arg0)
        return tArg0[0]

    def getIntArg1(self):
        tArg1 = unpack('<I', self.arg1)
        return tArg1[0]

    def getArg1(self):
        return self.arg1

    def getInfo(self):
        return self.info

    def setInfo(self, information):
        self.info = information

    def getDirection(self):
        return self.direction

    def getBusId(self):
        return self.busId

    def getDeviceAddress(self):
        return self.deviceAddress

    def getPacket(self):
        return self.packet

    def getCommand(self):
        return self.command

    def getDataLenght(self):
        tDataLenght = unpack('<I',self.data_length)
        return tDataLenght[0]

    def setPayload(self,packet_reader):
        packet = readNextUsbPacket(packet_reader)
        self.payload = b''
        try:
            while (True):
                if self.getBusId() == packet.bus and self.getDeviceAddress() == packet.device and self.getDirection() == packet.fields["info"]:
                    # Next packet with same direction
                    packetPayload = packet.payload
                    if packetPayload.raw_packet_cache is not None:
                        if len(packetPayload) == self.getDataLenght():
                            self.payload = packetPayload.raw_packet_cache
                            break
                        # Message broken in multiples USB packets
                        elif len(packetPayload) < self.getDataLenght():
                            self.payload = self.payload + packetPayload.raw_packet_cache
                            if len(self.payload) == self.getDataLenght():
                                break
                            elif len(self.payload) > self.getDataLenght():
                                raise PacketException("Wrong payload size")
                        else:
                            raise PacketException("Wrong payload size")
                packet = readNextUsbPacket(packet_reader)
        except EOFError:
            raise PacketException("Wrong payload size")

    def getPayload(self):
        if self.payload is not None:
            return self.payload
        return None


class PacketException(Exception):
    def __init__(self, message="Packet is incorrect"):
        self.message = message
        super().__init__(self.message)

#
# https://android.googlesource.com/platform/packages/modules/adb/+/master/protocol.txt
# Messages
# define A_SYNC 0x434e5953
# define A_CNXN 0x4e584e43
# define A_AUTH 0x48545541
# define A_OPEN 0x4e45504f
# define A_OKAY 0x59414b4f
# define A_CLSE 0x45534c43
# define A_WRTE 0x45545257
# define A_STLS 0x534C5453

messageType = {
    "A_SYNC": b'SYNC',
    "A_CNXN": b'CNXN',
    "A_AUTH": b'AUTH',
    "A_OPEN": b'OPEN',
    "A_OKAY": b'OKAY',
    "A_CLSE": b'CLSE',
    "A_WRTE": b'WRTE',
    "A_STLS": b'STLS'
}

##
# Requesting the sync service ("sync:") using the protocol as described in
# SERVICES.TXT sets the connection in sync mode. This mode is a binary mode that
# differs from the regular adb protocol. The connection stays in sync mode until
# explicitly terminated (see below).
#
# In sync mode both the server and the client will frequently use eight-byte
# packets to communicate. In this document these are called sync requests and sync
# responses. The first four bytes are an id that specifies the sync request. It is
# represented by four utf-8 characters. The last four bytes are a Little-Endian
# integer, with various uses.
#
# Defs in file_sync_service.h (subcommands of sync op)
# struct SyncRequest {
#     uint32_t id;  // ID_STAT, et cetera.
#     uint32_t path_length;  // <= 1024
#     // Followed by 'path_length' bytes of path (not NUL-terminated).
# } __attribute__((packed)) ;
#

class SyncRequest():
    def __init__(self, packetPayload):
        self.id = packetPayload[0:4]
        self.syncPayload = None
        # Syncmessage may be fragmented
        # Ex:
        # 1 - WRTE
        # 2 - DONE
        # 3 - WRTE
        # 4 - nnnn
        if(len(packetPayload) >= 8):
            self.path_lenght = packetPayload[4:8]
        else:
            self.path_lenght = None
        if self.path_lenght is not None and self.getPathLenght() != 0:
            self.syncPayload = packetPayload[8: 8+self.getPathLenght()]

    def getId(self):
        return self.id

    def getPathLenght(self):
        tPathLenght = unpack('<I',self.path_lenght)
        return tPathLenght[0]

    def getSyncPayload(self):
        return self.syncPayload
#
#   define ID_STAT MKID('S','T','A','T')
#   define ID_LIST MKID('L','I','S','T')
#   define ID_SEND MKID('S','E','N','D')
#   define ID_RECV MKID('R','E','C','V')
#   define ID_DENT MKID('D','E','N','T')
#   define ID_DONE MKID('D','O','N','E')
#   define ID_DATA MKID('D','A','T','A')
#   define ID_OKAY MKID('O','K','A','Y')
#   define ID_FAIL MKID('F','A','I','L')
#   define ID_QUIT MKID('Q','U','I','T')

syncRequests = {
    "ID_STAT": b'STAT',
    "ID_STAT2": b'STA2',
    "ID_LIST": b'LIST',
    "ID_SEND": b'SEND',
    "ID_RECV": b'RECV',
    "ID_DENT": b'DENT',
    "ID_DONE": b'DONE',
    "ID_DATA": b'DATA',
    "ID_OKAY": b'OKAY',
    "ID_FAIL": b'FAIL',
    "ID_QUIT": b'QUIT'
}

SHELL_SESSION = b"shell"
SYNC_SESSION = b"sync"

def readNextUsbPacket(packet_reader):
    rawPacket = packet_reader.read_packet(size=MAXBUFFSIZE)
    packet = scapy.layers.usb.USBpcap(rawPacket[0])
    return packet

def getNextWRTEorCLSEMessage(messages, sessionIds):
    for message in messages:
        try:
            if message.getCommand() == messageType.get("A_CLSE"):
                # File transfer aborted
                if isSameSession(message,sessionIds):
                    raise PacketException("File transfer incomplete")
            if message.getCommand() == messageType.get("A_WRTE"):
                if isSameSession(message,sessionIds):
                    #if messageOrg.getBusId() == message.getBusId() and messageOrg.getDeviceAddress() == message.getDeviceAddress():
                    return message
        except EOFError:
            raise PacketException("File incomplete")
    raise PacketException("File incomplete or Connection closed")

def getNextSENDorRECVMessage(messages, sessionIds):
    for message in messages:
        try:
            if message.getCommand() == messageType.get("A_CLSE"):
                # File transfer aborted
                if isSameSession(message,sessionIds):
                    raise PacketException("File transfer incomplete")
            if message.getCommand() == messageType.get("A_WRTE"):
                if isSameSession(message,sessionIds):
                    #if messageOrg.getBusId() == message.getBusId() and messageOrg.getDeviceAddress() == message.getDeviceAddress():
                    if isSyncRequest(message.getPayload()[0:4]):
                        syncRequest = SyncRequest(message.getPayload())
                        if syncRequest.getId() == syncRequests.get("ID_SEND") or syncRequest.getId() == syncRequests.get("ID_RECV"):
                            return message
        except EOFError:
            raise PacketException("File incomplete")

def isOpenMessage(message):
    if message.getCommand() == messageType.get("A_OPEN"):
        return True
    return False

def isQuitSyncMessage(message):
    syncRequest = getSyncRequest(message)
    if syncRequest is not None:
        if syncRequest.getId() == syncRequests.get("ID_QUIT"):
            return True
    return False


def getSyncRequest(message):
    if (message.getPayload() != None):
        if isSyncRequest(message.getPayload()[0:4]):
            syncRequest = SyncRequest(message.getPayload())
            return syncRequest
    return None


def isDataSyncMessage(message):
    syncRequest = getSyncRequest(message)
    if syncRequest is not None:
        if syncRequest.getId() == syncRequests.get("ID_DATA"):
            return True
    return False

def isSameSession(message, sessionIds):
    if (message.getArg1() == sessionIds[0] and message.getArg0() == sessionIds[1]) or (message.getArg1() == sessionIds[1] and message.getArg0() == sessionIds[0]):
        return True
    return False

def readShellSession(messages, sessionIds):
    shellBuffer = b""
    for message in messages:
        try:
            if message.getCommand() == messageType.get("A_CLSE"):
                if isSameSession(message,sessionIds):
                    # End of session
                    break
            if message.getCommand() == messageType.get("A_WRTE"):
                if isSameSession(message,sessionIds):
                    shellBuffer = shellBuffer + message.getPayload()
        except EOFError:
            raise PacketException("Shell session incomplete")
    return shellBuffer

def readFile(messageOpen, messages, sessionIds):
    # https://android.googlesource.com/platform/packages/modules/adb/+/master/SYNC.TXT
    # After this the actual file is sent in chunks. Each chunk has the following
    # format.
    # A sync request with id "DATA" and length equal to the chunk size. After
    # follows chunk size number of bytes. This is repeated until the file is
    # transferred. Each chunk must not be larger than 64k.
    # When the file is transferred a sync request "DONE" is sent, where length is set
    # to the last modified time for the file. The server responds to this last
    # request (but not to chunk requests) with an "OKAY" sync response (length can
    # be ignored).

    message = getNextSENDorRECVMessage(messages,sessionIds)
    syncRequest = SyncRequest(message.getPayload())

    try:
        fileBuffer = b""
        fileBuffer = fileBuffer + message.getPayload()

        # https://android.googlesource.com/platform/packages/modules/adb/+/master/SYNC.TXT
        # SEND:
        # The remote file name is split into two parts separated by the last
        # comma (","). The first part is the actual path, while the second is a decimal
        # encoded file mode containing the permissions of the file on device.
        nextMessage = getNextWRTEorCLSEMessage(messages[messages.index(message)+1:], sessionIds)
        path = ""
        try:
            while(isQuitSyncMessage(nextMessage) is False):
                if nextMessage.getPayload() != None:
                    fileBuffer = fileBuffer + nextMessage.getPayload()
                nextMessage = getNextWRTEorCLSEMessage(messages[messages.index(nextMessage)+1:], sessionIds)
            path = path + getFilePath(fileBuffer)
            filename = getFileName(path)
            sizeSyncRequest = syncRequest.getPathLenght() + 8
            writeFileToOutput(fileBuffer[sizeSyncRequest:], filename, syncRequest)
        except PacketException as e:
            path = path + getFilePath(fileBuffer)
            path = path + " (" + e.message + ")"
    except Exception as e:
        return e.message
    if syncRequest.getId() == syncRequests.get("ID_SEND"):
        messageOpen.setInfo(" adb push " + path + " ***** File Transmission *****     ")
    else:
        messageOpen.setInfo(" adb pull " + path + " ***** File Transmission *****     ")
    return path


def writeFileToOutput(fileBuffer, filename, syncRequest):
    dirPath = os.getcwd()
    if syncRequest.getId() == syncRequests.get("ID_RECV"):
        dirPath = dirPath + OUTPUTDIR_PULL
    else:
        dirPath = dirPath + OUTPUTDIR_PUSH
    if not os.path.exists(dirPath):
        os.mkdir(dirPath)
    fullFileName = dirPath + "/" + filename
    if os.path.isfile(fullFileName):
        outFile = open(fullFileName + "_" + str(random.randint(0, 1000)), "wb")
    else:
        outFile = open(fullFileName, "wb")
    outFile.write(readChunks(fileBuffer))
    outFile.close()


def readChunks(fileBuffer):
    # First Data request
    fileData = b''
    syncRequest = SyncRequest(fileBuffer[0:])
    nextSyncPos = 0
    while syncRequest.getId() != syncRequests.get("ID_DONE"):
        fileData = fileData + syncRequest.getSyncPayload()
        sizeSyncRequest = syncRequest.getPathLenght()+8
        nextSyncPos = nextSyncPos + sizeSyncRequest
        syncRequest = SyncRequest(fileBuffer[nextSyncPos:])
    return fileData

def getFileName(path):
    pathSplit = path.split('/')
    return pathSplit[len(pathSplit) - 1]

def getFilePath(fileBuffer):
    syncRequest = SyncRequest(fileBuffer)
    strPayload = syncRequest.getSyncPayload().decode("utf8")
    path = strPayload.split(',')[0]
    return path


def isMessage(initialBytes):
    if (initialBytes in messageType.values()):
        return True;
    return False;

def isSyncRequest(initialBytes):
    if (initialBytes in syncRequests.values()):
        return True;
    return False;

def printSessions(messages):
    dirPath = os.getcwd() + OUTPUTDIR
    if not os.path.exists(dirPath):
        os.mkdir(dirPath)
    fullFileName = dirPath + "/" + SESSIONS_FILE
    if os.path.isfile(fullFileName):
        outFile = open(fullFileName + "_" + str(random.randint(0, 1000)), "w")
    else:
        outFile = open(fullFileName, "w")

    for message in messages:
        packet = message.getPacket()
        busId = str(packet.bus)
        deviceAdd = str(packet.device)
        if (packet.fields["info"] == 0):
            direction = "host -> " + busId + "." + deviceAdd
        else:
            direction = busId + "." + deviceAdd + " -> host"
        messageType = direction + ": " + message.getCommand().decode("ascii") + " (Arg 0: " + str(message.getIntArg0()) + ", Arg 1: " + str(message.getIntArg1()) + ", Lenght: " + str(message.getDataLenght()) + ")\n"
        header = "*************************** SESSION BEGIN ***************************\n"
        print(header)
        outFile.write(header)
        print(messageType)
        outFile.write(messageType)
        if message.getPayload() is not None:
            if message.getInfo() is not None:
                messagePayload = "\nPayload: " + message.getPayload().decode("ascii",errors="ignore") + "\n"+ message.getInfo() + "\n"
            else:
                messagePayload = "\nPayload: " + message.getPayload().decode("ascii",errors="ignore") + "\n"
            print(messagePayload)
            outFile.write(messagePayload)
        footer = "*************************** SESSION END ***************************\n\n\n"
        print(footer)
        outFile.write(footer)
    outFile.close()

def printMessages(messages):
    dirPath = os.getcwd() + OUTPUTDIR
    if not os.path.exists(dirPath):
        os.mkdir(dirPath)
    fullFileName = dirPath + "/" + MESSAGES_FILE
    if os.path.isfile(fullFileName):
        outFile = open(fullFileName + "_" + str(random.randint(0, 1000)), "w")
    else:
        outFile = open(fullFileName, "w")

    for message in messages:
        packet = message.getPacket()
        busId = str(packet.bus)
        deviceAdd = str(packet.device)
        if (packet.fields["info"] == 0):
            direction = "host -> " + busId + "." + deviceAdd
        else:
            direction = busId + "." + deviceAdd + " -> host"
        messageType = direction + ": " + message.getCommand().decode("ascii") + " (Arg 0: " + str(message.getIntArg0()) + ", Arg 1: " + str(message.getIntArg1()) + ", Lenght: " + str(message.getDataLenght()) + ")\n"
        print(messageType)
        outFile.write(messageType)

    outFile.close()


def isShellSession(message):
    if message.getCommand() == messageType.get("A_OPEN"):
        initialBytes = message.getPayload()[0:5]
        if (initialBytes  == SHELL_SESSION):
            return True;
    return False;

def isSyncSession(message):
    if message.getCommand() == messageType.get("A_OPEN"):
        initialBytes = message.getPayload()[0:4]
        if (initialBytes  == SYNC_SESSION):
            return True;
    return False;

# Script reads sessions started by OPEN messages
#
# OPEN(local-id, 0, "destination")
# The OPEN message informs the recipient that the sender has a stream
# identified by local-id that it wishes to connect to the named
# destination in the message payload.  The local-id may not be zero.
#
# CLOSE(local-id, remote-id, "")
# The CLOSE message informs recipient that the connection between the
# sender's stream (local-id) and the recipient's stream (remote-id) is
# broken.  The remote-id MUST not be zero, but the local-id MAY be zero
# if this CLOSE indicates a failed OPEN.
#
#
# Ex:
# Host -> Device
# 4f 50 45 4e - OPEN
# 1e 00 00 00 - Local-id
# 00 00 00 00 - 0
# 06 00 00 00 - destination
# f7 01 00 00
# b0 af ba b1
#
# Device -> Host
# 43 4c 53 45 - CLSE
# 08 00 00 00 - Local-id
# 1e 00 00 00 - Remote-id
# 00 00 00 00 - ""
# 00 00 00 00 -
# bc b3 ac ba -
#
# Host -> Device
# 43 4c 53 45 - CLSE
# 1e 00 00 00 - Local-id
# 08 00 00 00 - Remote-id
# 00 00 00 00 - ""
# 00 00 00 00
# bc b3 ac ba
def parseMessages(pcapFilePath):
    load_layer("usb")
    packet_reader = RawPcapNgReader(pcapFilePath)

    # Output directory
    dirPath = os.getcwd() + OUTPUTDIR
    if not os.path.exists(dirPath):
        os.mkdir(dirPath)

    messages = []

    while True:
        try:
            # Default buffer = 65536, not enough to USB packets
            # buffer set to 1MB (problem with rdpcap)
            #
            # USBPcap with 10 MB buffer
            # Ex: C:\Program Files\USBPcap>USBPcapCMD.exe --snaplen 10485760 --bufferlen 10485760 --device \\.\USBPcap1 -A -o usbCapture.pcap
            #
            rawPacket = packet_reader.read_packet(size=MAXBUFFSIZE)  # read packet up to 1MB large
            packet = scapy.layers.usb.USBpcap(rawPacket[0])
            packetPayload = packet.payload
            if (packetPayload.raw_packet_cache != None):
                if (isMessage(packetPayload.raw_packet_cache[0:4])):
                    message = Message(packet,packet_reader)
                    messages.append(message)
        except EOFError:
            break

    sessionList = []
    for i in range(0,len(messages)):
        try:
            message = messages[i]
            if (message.getPayload() != None):
                # Output only sessions
                if isOpenMessage(message):
                    sessionIds = getSessionIds(message,messages[i:])
                    # get shell session
                    if isShellSession(message):
                        shellBuffer = readShellSession(messages[i:], sessionIds)
                        message.setInfo(shellBuffer.decode("utf8",errors="ignore"))
                        sessionList.append(message)
                    # Get files from adb push and pull
                    if isSyncSession(message):
                        readFile(message, messages[i:], sessionIds)
                        sessionList.append(message)
        except PacketException as e:
            print(e.message)

    printMessages(messages)
    printSessions(sessionList)

def getSessionIds(message,messages):
    openId = message.getArg0()
    okId = None
    for newMessage in messages:
        if newMessage.getCommand() == messageType.get("A_OKAY"):
            if newMessage.getArg1() == message.getArg0():
                okId = newMessage.getArg0()
                break
        if newMessage.getCommand() == messageType.get("A_CLSE"):
            if newMessage.getArg0() == message.getArg0():
                raise PacketException("Session Closed")
    if okId is None:
        raise PacketException("Session Closed")
    return openId,okId

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 adbPcapReader capture.pcap")
        quit()
    pcapFilePath = sys.argv[1]
    parseMessages(pcapFilePath)

if __name__ == '__main__':
    main()