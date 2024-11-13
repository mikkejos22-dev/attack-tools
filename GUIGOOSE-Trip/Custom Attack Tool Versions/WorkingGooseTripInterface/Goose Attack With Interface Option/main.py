from flask import Flask, render_template, request
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
from lib import attack, goose
import socket
import psutil # Used for getting availible interfaces

IP_TARGET = '192.168.219.30'
INTERFACE = 'Wi-Fi'
app = Flask(__name__)

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
    return available_interfaces[:-2] # to remove last delimeter
    
    
@app.route('/')
def show_default_page():
    return render_template('ied.html')


@app.route('/update/target', methods=['POST', 'GET'])
def update_plc_ip():
    global IP_TARGET
    if request.method == 'GET':
        return IP_TARGET
    elif request.method == 'POST':
        try:
            socket.inet_aton(request.form['ip'])
            IP_TARGET = request.form['ip']
            logger.info('[Settings: Target address changed] ' + IP_TARGET)
            return "OK"
        except socket.error:
            return IP_TARGET

@app.route('/update/interface', methods=['POST', 'GET'])
def update_interface():
    global INTERFACE
    if request.method == 'GET':
        return getActiveInterfaceArray()
    elif request.method == 'POST':
        try:
            INTERFACE = request.form['interface']
            logger.info('[Settings: Interface name changed] ' + INTERFACE)
            return "OK"
        except socket.error:
            return INTERFACE


@app.route('/status/plc', methods=['GET'])
def return_status_plc():
    status_plc = attack.plc_status_check(IP_TARGET)
    return status_plc


@app.route('/status/ping', methods=['GET'])
def return_status_ied1():
    status_ied1 = attack.ping_status_check(IP_TARGET)
    return status_ied1


@app.route('/status/log', methods=['GET'])
def read_log():
    with open("attack.log", "r") as file:
        file_content = file.readlines()
        log_content = ''
        for line in range(len(file_content)):
            log_content += file_content[-(line + 1)] + "<br>"
            if line > 29:
                break
    return log_content


@app.route('/attack/ied/goose/trip620', methods=['POST'])
def execute_goose_trip620():
    logger.info('[GOOSE: Trip] Mimicking trip command from REF620 '
                + goose.ref620_trip(INTERFACE))
    return 'OK'


@app.route('/attack/ied/goose/untrip620', methods=['POST'])
def execute_goose_untrip620():
    logger.info('[GOOSE: unTrip] Mimicking untrip command from REF620'
                + goose.ref620_untrip(INTERFACE))
    return 'OK'


def init_log():
    global logger
    log_handler = ConcurrentRotatingFileHandler('attack.log', maxBytes=10000, backupCount=3)
    log_format = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    log_handler.setFormatter(log_format)
    logger = logging.getLogger("Attack_log")
    logger.setLevel(logging.INFO)
    logger.addHandler(log_handler)


if __name__ == "__main__":
    init_log()
    app.run(host='0.0.0.0')
    # app.run(debug=True)
