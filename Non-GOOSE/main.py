import time
import struct
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.all import *
from scapy.layers.ntp import TimeStampField
import datetime
from binascii import unhexlify
def num2str(num):
    bytestring = bytearray()
    if num // 256 // 256 // 256 // 256 % 256 > 0:
        bytestring.append(num // 256 // 256 // 256 // 256 % 256)
    if num // 256 // 256 // 256 % 256 > 0:
        bytestring.append(num // 256 // 256 // 256 % 256)
    if num // 256 // 256 % 256 > 0:
        bytestring.append(num // 256 // 256 % 256)
    if num // 256 % 256 > 0:
        bytestring.append(num // 256 % 256)
    bytestring.append(num % 256)
    return bytestring
def construct_rgoose_packet():
    class GoosePDU(Packet):
        name = "Goose PDU"
        fields_desc = [ByteField("sequence_t", 0x61),
                       ConditionalField(ByteField("sequence_el", 0x81), lambda pkt: pkt.sequence_l > 127),
                       ByteField("sequence_l", 0),
                       ByteField("gocbRef_t", 0x80),
                       FieldLenField("gocbRef_l", None, length_of="gocbRef", fmt="B"),
                       StrLenField("gocbRef", None, length_from=lambda pkt: pkt.gocbRef_l),
                       ByteField("timeAllowedtoLive_t", 0x81),
                       FieldLenField("timeAllowedtoLive_l", None, length_of="timeAllowedtoLive", fmt="B"),
                       StrLenField("timeAllowedtoLive", None, length_from=lambda pkt: pkt.timeAllowedtoLive_l),
                       ByteField("datSet_t", 0x82),
                       FieldLenField("datSet_l", None, length_of="datSet", fmt="B"),
                       StrLenField("datSet", None, length_from=lambda pkt: pkt.datSet_l),
                       ByteField("goID_t", 0x83),
                       FieldLenField("goID_l", None, length_of="goID", fmt="B"),
                       StrLenField("goID", None, length_from=lambda pkt: pkt.goID_l),
                       ByteField("T_t", 0x84),
                       ByteField("T_l", 8),
                       TimeStampField("T", None),
                       ByteField("stNum_t", 0x85),
                       FieldLenField("stNum_l", 1, fmt="B"),
                       StrLenField("stNum", None, length_from=lambda pkt: pkt.stNum_l),
                       ByteField("sqNum_t", 0x86),
                       FieldLenField("sqNum_l", None, length_of="sqNum", fmt="B"),
                       StrLenField("sqNum", None, length_from=lambda pkt: pkt.sqNum_l),
                       ByteField("simulation_t", 0x87),
                       ByteField("simulation_l", 1),
                       ByteField("simulation", None),
                       ByteField("confRev_t", 0x88),
                       ByteField("confRev_l", 2),
                       ShortField("confRev", 700),
                       ByteField("ndsCom_t", 0x89),
                       ByteField("ndsCom_l", 1),
                       ByteField("ndsCom", None),
                       ByteField("numDatSetEntries_t", 0x8a),
                       FieldLenField("numDatSetEntries_l", None, length_of="numDatSetEntries", fmt="B"),
                       StrLenField("numDatSetEntries", None, length_from=lambda pkt: pkt.numDatSetEntries_l)
                       ]
    """
    Constructs a valid R-GOOSE (Routable GOOSE) packet with correct headers.
    """
    # Ethernet and IP details
    src_mac = "00:1B:21:98:79:48"  # Change to your MAC
    dst_mac = "01:0c:cd:01:00:01"  # Standard R-GOOSE multicast MAC: 01:0C:CD:01:00:01
    src_ip = "137.104.91.31"  # Change to your IP
    dst_ip = "239.255.0.1"  # Multicast IP for R-GOOSE: 239.255.0.1
    src_port = 10200 # ✅ Corrected port for R-GOOSE
    dst_port = 102

    # ✅ Properly encoded GOOSE message (BER encoding)
    Headers = bytes.fromhex(
        #Ethernet Layer
        "01 00 5e 00 01 01 08 00 27 bf f8 81 08 00"
        #IP layer
        "45 00 "  # Version, Differentied services field
        "00 cb " # Length
        "a1 c6 " # Identification
        "40 00 " # Fragment Flags
        "10 " #TTL 
        "11 "  #UDP
        "3c c3 " #Header Checksum
        #UDP Layer
        "89 68 5b 1f" #SRC IP
        "ef c0 00 01" #DST IP
        "cc b2 " #src port
        "27 d8 " #Dst port
        "00 b7 " # length
        "92 ec "#Checksum
        #ISO 8602/X.234 CLTP ConnectionLess Transport Protocol
        "01 " # length
        "42 " # PDU Type: UD
        "a1 18 80 1a 00 00 00 af 00 00 00 0d 00 01 00 00 00 00 00 00 00 00 00 00" #Secruity Information
        "00 00 00 00" # header buffer
        "87" #Length
        "81" #Payload Tag
        "00" # simulation tag
        "00 04" # APPID
        "00 90" # currently 120 is as far the payload goes + 33 total
    )
    class GooseHeader(Packet):
        name = "Goose Header"
        fields_desc = [ShortField("length", 147),
                       ShortField("appid", 1)]

    goose_pdu = GoosePDU(gocbRef="REF62030LD0/LLN0$GO$gcbREF620",
                         timeAllowedtoLive=num2str(20000),
                         datSet="REF62030LD0/LLN0$REF620",
                         goID="REF62030LD0/LLN0.gcbREF620",
                         T=datetime.datetime.now(datetime.timezone.utc).timestamp(),
                         stNum=num2str(237),
                         sqNum=num2str(3),
                         simulation=0,
                         confRev=700,
                         ndsCom=0,
                         numDatSetEntries=num2str(4)
                         )
    goose_data = unhexlify("ab1084030300008301018403030000830100")
    goose_pdu.sequence_l = (144)
    print(len(goose_pdu))

    print((len(goose_pdu) + len(goose_data)) - 2)
    goose_header = GooseHeader(appid=4, length=160)
    print(goose_header.show())
    goose_packet = Headers/ goose_pdu / goose_data
    print(goose_pdu)
    #GET GOOSE HEADER INFORMATION CORRECT FIRST
        #R-GOOSE HMAC
        #"a1 18 80 16 00 00 00 97 00 00 00 08 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" #Session header
        #"83 81 00 00 05 00 7b 61 79 80 1c 4c 44 31 2f 4c 4c 4e 30 2e 43 42 32 32 5f 53 74 61 74 75 73 2d 52 2d 47 4f 4f 53 45 81 01 14 82 15 4c 44 31 2f 4c 4c 4e 30 2e 53 74 61 74 75 73 6f 66 43 42 32 32 83 1c 4c 44 31 2f 4c 4c 4e 30 2e 43 42 32 32 5f 53 74 61 74 75 73 2d 52 2d 47 4f 4f 53 45 84 08 67 3e 22 23 69 4a 61 0a 85 01 06 86 01 00 87 01 00 88 01 01 89 01 00 8a 01 01 ab 03 83 01 00 85 00") #Session User information
    # ✅ Add the R-GOOSE Header (APPID, Length, Reserved)
    print(len(goose_packet))
    print(len(goose_packet))
    # ✅ Prepend the R-GOOSE Header
    rgoose_packet = goose_packet

    return rgoose_packet

def send_rgoose():
    """
    Sends the R-GOOSE packet on the network.
    """
    packet = construct_rgoose_packet()
    i = 0
    while(i < 100):
        sendp(packet, iface="Ethernet 5")  # Change 'Wi-Fi' to your network interface
        i = i + 1

if __name__ == "__main__":
    print("Sending R-GOOSE message...")
    send_rgoose()
