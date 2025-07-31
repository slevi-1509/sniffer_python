from scapy.all import sniff, DNS, DNSQR, DNSRR
from scapy import interfaces
from itertools import count
from time import ctime
import ipaddress
import json
import time
import os
import socket
# import threading
import redis
# import pymongo
import sys
import nmap
from openai_request import get_openai_response
import multiprocessing

# import concurrent.futures

def get_config():
    config_file_path = "sniffer.conf"
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
        
def handle_packet(packet, network, log_file, config, new_devices):
    try:
        # pkt_time = ctime(packet.time)
        # pack_dict = json.loads(packet.json())
        pack_sum = {'timestamp': ctime(packet.time),
                    'src_mac': packet.src.upper(), 
                    'src_ip': packet.payload.src
                    }
        if ipaddress.ip_address(pack_sum['src_ip']) in network:  
            # doc_exist = mongo_col.find_one({ 'src_mac': pack_sum['src_mac'] })
            # mac_exist = r.exists(pack_sum['src_mac'])
            if pack_sum['src_mac'] not in new_devices.keys():
                print("New device detected:", pack_sum)
                new_devices[pack_sum['src_mac']] = [pack_sum['src_ip'], pack_sum['timestamp']]
            # elif mac_exist['src_ip'] != pack_sum['src_ip']:
            #     pass
                # mongo_col.update_one({ 'src_mac': pack_sum['src_mac'] }, { '$set': { 'timestamp' : pkt_time, 'src_ip': pack_sum['src_ip'] } })
        pack_sum = {**pack_sum,
                'dst_mac': packet.dst,
                'dst_ip': packet.payload.dst,
                'src_port': packet.payload.payload.sport if 'sport' in packet.payload.payload else None,
                'dst_port': packet.payload.payload.dport if 'dport' in packet.payload.payload else None,
                'protocol': packet.payload.proto if 'proto' in packet.payload else None,
                'ip_version': packet.payload.version}
        
        if packet.haslayer(DNS) and pack_sum['dst_port'] == 53:
            pack_sum['dns_query'] = packet[DNSQR].qname.decode('utf-8') if packet.haslayer(DNSQR) else None
            pack_sum['dns_answer'] = packet[DNSRR].rdata.decode('utf-8') if packet.haslayer(DNSRR) else None
            if handle_dns(pack_sum['dns_query'], config):
                handle_error('dns', pack_sum['dns_query'], pack_sum)
                
        print(pack_sum)
        log_file.write(f"{pack_sum}\n")
        # packets.append(pack_sum)
    except KeyboardInterrupt:
                sys.exit(0)

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
        
def newDeviceExists(new_devices):
    r = redis.Redis(host='localhost', port=6379, db=0)
    for device in new_devices.items():
        mac_exist = r.exists(device[0])
        if mac_exist:
            continue
        host_name = get_hostname_from_ip(device[1][0])
        vendor_name = get_vendor_name(device[1][0], device[0])
        port_scan_result = start_scan_ports(device[1][0])
        pack_sum = {'timestamp': device[1][1],
                    'src_mac': device[0],
                    'src_ip': device[1][0],
                    'vendor': vendor_name,
                    'host_name': host_name,
                    'port_scan_result': port_scan_result
                    }
        ai_response = get_openai_response(pack_sum)
        try:
            r.hset(device[0], "timestamp", str(device[1][1]))
            r.hset(device[0], "src_ip", str(device[1][0]))
            r.hset(device[0], "is_IOT", str(ai_response))
            r.hset(device[0], "vendor", str(vendor_name))
            r.hset(device[0], "host_name", str(host_name))
            r.hset(device[0], "port_scan_result", str(port_scan_result))
        except redis.exceptions.ResponseError as e:
            print(f"Redis error: {e}")
        
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
        return None
    except Exception as e:
        return f"An error occurred: {e}"

def start_scan_ports(host):
    open_ports = []
    scan_port(host, open_ports)
    # print(open_ports)
    return open_ports

def scan_port(host, open_ports):
    try: 
        i = 0
        for port in range(0, 1024):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            # print(f"{i} - IP {host} - Port {port} - Result: {result}")
            i += 1
            if result == 0:
                # return("Port {} is open".format(port))
                open_ports.append(f"Port {port} is open")
                print(f"Port {port} is open on {host}")
            elif result == 10013:  # Connection refused
                open_ports.append(f"Port {port} is open on {host} but permission denied")
                print(f"Port {port} is open on {host} but permission denied")
            elif result == 10048:  # Address already in use
                open_ports.append(f"Port {port} is already in use on {host}")
                print(f"Port {port} is already in use on {host}")
            elif result == 10054:  # Connection reset by peer
                open_ports.append(f"Port {port} connection reset by peer on {host}")
                print(f"Port {port} connection reset by peer on {host}")
            elif result == 10056:  # Port is already in use
                open_ports.append(f"Port {port} is already in use on {host}")
                print(f"Port {port} is already in use on {host}")
            elif result == 10061:  # The target machine actively refused it
                open_ports.append(f"Port {port} is closed on {host}")
                print(f"Port {port} is closed on {host}")
            else:
                print(f"Port: {port} , socket code: {result}")
    except KeyboardInterrupt:
        sys.exit(0)
    except socket.error as e:
        print(f"Socket error: {e}")
    
def main(interval, packets_count, no_of_sessions=0):
    interface = interfaces.get_working_if()
    network = ipaddress.ip_network(f"{interface.ip}/24", strict=False)
    # host = 'localhost'
    # start_port = 1
    # end_port = 1000
    # mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
    # mongo_db = mongo_client["mydatabase"]
    # mongo_col = mongo_db["devices"]
    # packets = []
    log_file_path = "sniffer.log"
    config = get_config()
    filter = "tcp or udp or icmp"
    with open(log_file_path, "a") as log_file:
        try:
            processes = []
            for i in count(0):
                new_devices = {}
                sniff(iface=interface, filter=filter, prn=lambda pkt: handle_packet(pkt, network, log_file, config, new_devices), 
                      count=packets_count, store=0)
                if i == no_of_sessions-1:
                    break
                if new_devices:
                    process = multiprocessing.Process(target=newDeviceExists, args=(new_devices,))
                    # process.daemon = True  # Set the process as a daemon
                    process.start()  # start process to handle new device
                    processes.append(process)
                process.join()
                time.sleep(interval)
            # for process in processes:       
            #     process.join()  # wait for process to finish
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
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
    main(1, 1000, 5)