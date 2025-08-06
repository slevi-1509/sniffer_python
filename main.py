from flask import Flask, request, Response
from flask_cors import CORS
from scapy.all import sniff, DNS, DNSQR, DNSRR, TCP
from scapy import interfaces
from itertools import count
from datetime import datetime
import ipaddress
import json
import time
import os
import socket
# import threading
import nmap
# import multiprocessing
import requests
import ast

app = Flask(__name__)
CORS(app) 

def get_config():
    config_file_path = "config.json"
    if not os.path.exists(config_file_path):
        print(f"Configuration file {config_file_path} not found.")
        return []
    with open(config_file_path, "r") as conf_file:
        try:
            conf_data = json.load(conf_file)
            return conf_data
        except json.JSONDecodeError as e:
            print(f"Error reading configuration file: {e}")
            return []   
        
def handle_packet(packet, network, config, new_devices, collect_data_time, iot_probability):
    if ipaddress.ip_address(packet.payload.src) not in network:
        return
    if (packet.src.upper() in registered_devices):
        is_IOT = int(registered_devices[packet.src.upper()].get("is_IOT").replace("%", ''))
        if is_IOT < iot_probability:
            print(f"Device {packet.src.upper()} is not an IoT device (IoT probability: {is_IOT}%)")
            return
    tcp_window_size = float(packet[TCP].window) if packet.haslayer(TCP) else 0
    pack_sum = {
        "timestamp": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
        "src_mac": packet.src.upper(),
        "src_ip": packet.payload.src,
        "dst_mac": packet.dst,
        "dst_ip": packet.payload.dst,
        "src_port": packet.payload.payload.sport if "sport" in packet.payload.payload.fields else None,
        "dst_port": packet.payload.payload.dport if "dport" in packet.payload.payload.fields else None,
        "protocol": packet.payload.proto,
        "ip_version": packet.payload.version,
        "ttl": packet.payload.ttl,
        "tcp_window_size": tcp_window_size,
        "os": detect_os_fast(packet, tcp_window_size),
    }
    if packet.haslayer(DNS) and pack_sum["dst_port"] == 53:
        try:
            pack_sum["dns_query"] = packet[DNSQR].qname.decode("utf-8") if packet.haslayer(DNSQR) else None #payload(DNS).qd.0.qname
            # pack_sum["dns_answer"] = packet[DNSRR].rdata.decode("utf-8") if 'rdata' in packet[DNSRR] else None
        except Exception as e:
            print(f"Error decoding DNS data: {e}")
    if pack_sum["src_mac"] not in new_devices.keys() and packet.haslayer(TCP): # need to check why need tcp layer !!!
        # print("New device detected:")
        new_devices[pack_sum["src_mac"]] = pack_sum
    log_file_path = './logs/' + pack_sum["src_mac"].replace(":", "") + ".log"
    packet_exists = False
    line_dict = {}
    try:
        with open(log_file_path, "a+") as log_file:
            log_file.seek(0) 
            for line in log_file:
                # new_line = "{" + line.strip()[42:]
                line_dict = ast.literal_eval(line)
                if [line_dict["dst_mac"], line_dict["dst_ip"], line_dict["dst_port"], line_dict["protocol"]] == [pack_sum["dst_mac"], pack_sum["dst_ip"], pack_sum["dst_port"], pack_sum["protocol"]]:
                    packet_exists = True
                    break
            if not packet_exists:
                if len(line_dict) > 0:
                    format_string = "%Y-%m-%d %H:%M:%S"
                    last_packet_time = datetime.strptime(line_dict['timestamp'], format_string)
                    curr_packet_time = datetime.strptime(pack_sum['timestamp'], format_string)
                    time_diff_sec = (curr_packet_time - last_packet_time).total_seconds()
                    if time_diff_sec > collect_data_time:
                        handle_anomaly(pack_sum)
                log_file.write(f"{pack_sum}\n")
    except IOError as e:
        print(f"Error writing to log file {log_file_path}: {e}")    
    except Exception as e:
        print(f"An error occurred while processing the packet: {e}")
    print(pack_sum)
    
def handle_anomaly(pack_sum):
    anomaly_file_path = "anomalies.log"
    with open(anomaly_file_path, "a+") as log_file:
        anomaly = str(pack_sum).replace("'", '"').replace("None", '"None"') # Ensure JSON format
        log_file.write(f"{anomaly}\n")

def handle_dns(url, config):
    for entry in config['url']:
        if str(url).find(str(entry)) != -1:
            return True
    return False

def handle_error(error, url, packet):
    with open("sniffer_errors.log", "a") as log_file:
        match error:
            case 'dns':
                msg = (f"DNS query matched a forbidden URL: {url}\n{packet}")
                print(msg)
                log_file.write(f"{msg}\n")
            case '1':
                pass
            case _:
                pass

def newDeviceExists(new_devices, ports_scan, os_detect):
    for device in new_devices.values():
        if device['src_mac'] in registered_devices:
            continue
        host_name = get_hostname_from_ip(device['src_ip'])
        vendor_name = get_vendor_name(device['src_ip'], device['src_mac'])
        port_scan_result = scan_port(device['src_ip']) if ports_scan else None
        device_os = detect_os_long(device['src_ip']) if os_detect else 'Unknown OS'
        device = {**device,
                    'vendor': vendor_name,
                    'host_name': host_name,
                    'port_scan_result': port_scan_result,
                    'os': device_os,
                    }
        addDevice(device)

def addDevice(data):
    print("Sending AI request to determine if device is IoT")
    response = requests.post('http://localhost:5000/devices', json=data)
    if response.status_code == 201:
        device = response.json().get('device', {})
        file_path = "devices.json"
        data = {}
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as file:
                    data = json.load(file)
            with open(file_path, 'w') as file:
                data[device['src_mac']] = device
                json.dump(data, file, indent=4)
                print("Created Successfully")
        except Exception as e:
            print(f"Error writing to file: {e}")
    else:
        print("Error: Creation Failed") 
         
def get_vendor_name(ip, mac):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-sP')
        if mac not in nm[ip]['vendor'].keys():
            return "Unknown Vendor"
        else:
            vendor_name = nm[ip]['vendor'][mac]
            return vendor_name
    except Exception as e:
        print(f"Error occurred while scanning: {e}")
        return "Unknown Vendor"

def get_hostname_from_ip(ip):
    try:  
        hostname, _, _ = socket.gethostbyaddr(ip)      
        return hostname
    except socket.herror:
        return "Unknown Hostname"
    # except Exception as e:
    #     return f"An error occurred: {e}"

def scan_port(host):
    open_ports = ''
    ports_to_scan = [20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,162,443,445,500,514,520,554,631,993,995,1434,1723,1900,3306,3389,4500,5900,8080,49152]
    print(f"Scanning ports on {host}...")
    try: 
        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports += f"{port}: open, " 
            elif result == 10013:  # Connection refused
                open_ports += f"{port}: open but permission denied, "
            elif result == 10048:  # Address already in use
                open_ports += f"{port}: Address already in use, "
            elif result == 10054:  # Connection reset by peer
                open_ports += f"{port}: Connection reset by peer, "
            elif result == 10056:  # Port is already in use
                open_ports += f"{port}: already in use, "
            elif result == 10061:  # The target machine actively refused it
                open_ports += f"{port}: machine actively refused it, "
        try:
            r_http = requests.get(f"http://{host}/")
            if r_http.status_code == 200:
                open_ports += 'HTTP: service is running, '
            r_https = requests.get(f"https://{host}/")
            if r_https.status_code == 200:
                open_ports += 'HTTPS: service is running, '
        except requests.RequestException:
            open_ports += 'HTTPS: rejected by host, '
            return open_ports.strip(', ')
        return open_ports.strip(', ')
    except socket.error as e:
        print(f"Socket error: {e}")
    
def detect_os_fast(packet, tcp_window_size):
    if packet:
        if packet.payload.ttl <= 80 and tcp_window_size > 64000:
            return "Linux_Unix"
        elif packet.payload.ttl <= 140 and tcp_window_size > 64000:
            return "Windows"
        elif packet.payload.ttl <= 255 and tcp_window_size < 17000:
            return "Cisco_Solaris"
        else:
            return "Unknown OS"
        
def detect_os_long(ip):
    nm = nmap.PortScanner()
    print(f"Detecting Operating System for {ip}...")
    try:
        scan = nm.scan(hosts=ip, arguments='-O')
        if 'osmatch' in scan['scan'][ip]:
            return scan['scan'][ip]['osmatch'][0]['name']
        else:
            return "Unknown OS"
    except Exception as e:
        print(f"Error occurred while scanning: {e}")
        return "Unknown OS"
    
def main(interface, data):
    global registered_devices
    network = ipaddress.ip_network(f"{interface.ip}/24", strict=False)
    config = get_config()
    filter = "tcp or udp or icmp"
    # try:
        # processes = []
    for i in count(0):
        new_devices = {}
        sniff(iface=interface, filter=filter, prn=lambda pkt: handle_packet(pkt, network, config, new_devices, data['collect_data_time'], data['iot_probability']),
                count=data['no_of_packets'], store=0)
        if new_devices:
            newDeviceExists(new_devices, data['ports_scan'], data['os_detect'])
            devices_file_path = "devices.json"
            if os.path.exists(devices_file_path):
                    with open(devices_file_path, 'r') as file:
                        registered_devices = json.load(file)
            # process = multiprocessing.Process(target=newDeviceExists, args=(new_devices,))
            # # process.daemon = True  # Set the process as a daemon
            # process.start()  # start process to handle new device
            # processes.append(process)
        # process.join()
        time.sleep(data['interval'])
        if i == data['no_of_sessions']-1:
            break
        # for process in processes:       
        #     process.join()  # wait for process to finish
    # except KeyboardInterrupt:
    #     sys.exit(0)
            
@app.route("/api/runsniffer", methods=["POST"])
def startSniffer():
    data = request.get_json()
    response = Response("message Sniffer started", 200)
    @response.call_on_close
    def on_close():
        found_working_interfaces = interfaces.get_working_ifaces()
        for interface_item in found_working_interfaces:
            if data['interface'] == interface_item.name:
                interface = interface_item
        main(interface, data)
        print("Sniffer has finished running.")
    return response

@app.route("/api/interfaces", methods=["GET"])
def getInterfaces():
    working_interfaces = []
    found_working_interfaces = interfaces.get_working_ifaces()
    if not found_working_interfaces:
        return
    else:
        for i, interface in enumerate(found_working_interfaces):
            working_interfaces.append ({'interface': interface.name, 'ip': interface.ip})
    return working_interfaces, 200
    
@app.route("/api/anomalies", methods=["GET"])
def getAnomalies():
    anomalies_file_path = "anomalies.log"
    data = []
    try:
        if os.path.exists(anomalies_file_path):
            with open(anomalies_file_path, 'r') as file:
                for line in file:
                    data.append(line.strip())
        if not data:
            return "No anomalies found", 404
        return data, 200
    except Exception as e:
        print(f"Error getting anomalies file: {e}")
        return "internal server error", 500
    
@app.route("/api/devices", methods=["GET"])
def getDevices():
    data = list(registered_devices.values())
    # try:
    #     if os.path.exists(devices_file_path):
    #         with open(devices_file_path, 'r') as file:
    #             data = list(json.load(file).values())
    return data, 200
    # except Exception as e:
    #     print(f"Error getting devices file: {e}")
    #     return "internal server error", 500
    

if __name__ == "__main__":
    global registered_devices
    registered_devices = {}
    devices_file_path = "devices.json"
    if os.path.exists(devices_file_path):
            with open(devices_file_path, 'r') as file:
                registered_devices = json.load(file)
    app.run(host="0.0.0.0", port=5001)
    
    # interval = input("Enter the interval between sniffing packets sessions(in seconds): ")
    # packets_count = input("Enter the number of packets to sniff on each session: ")
    # no_of_sessions = input("Enter the number of sessions(0 for infinite): ")
    # try: 
    #     interval = int(interval)
    #     packets_count = int(packets_count)
    #     no_of_sessions = int(no_of_sessions)
    #     if interval <= 0 or packets_count <= 0 or no_of_sessions < 0:
    #         raise ValueError("Interval and packets count must be positive integers.")
    # except ValueError:
    #     print("Invalid input. Please enter integers for interval and packets count.")
    #     sys.exit(1)
    # main(interval, packets_count, no_of_sessions)
    # main(5, 10, 5)