from scapy.all import sniff, DNS, DNSQR, DNSRR
from scapy import interfaces
import ipaddress
import json
import time
from time import ctime
import os
import socket
import threading
import pymongo
import sys

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
        
def handle_packet(packet, network, packets, config, mongo_col):
    try:
        pkt_time = ctime(packet.time)
        pack_dict = json.loads(packet.json())
        pack_sum = {'timestamp': pkt_time,
                    'src_mac': pack_dict['src'], 
                    'dst_mac': pack_dict['dst'], 
                    'src_ip': pack_dict['payload']['src'],
                    'dst_ip': pack_dict['payload']['dst']}
        doc_exist = mongo_col.find_one({ 'src_mac': pack_sum['src_mac'] } )
        if doc_exist is None:
            if ipaddress.ip_address(pack_sum['src_ip']) in network:
                host_name = get_hostname_from_ip(pack_sum['src_ip'])
                mongo_col.insert_one({**pack_sum, 'host_name': host_name})
        elif doc_exist['src_ip'] != pack_sum['src_ip']:
            if ipaddress.ip_address(pack_sum['src_ip']) in network:
                mongo_col.update_one({ 'src_mac': pack_sum['src_mac'] }, { '$set': { 'src_ip': pack_sum['src_ip'] } })
        pack_sum = {**pack_sum,
                'src_port': pack_dict['payload']['payload']['sport'] if 'sport' in pack_dict['payload']['payload'] else None,
                'dst_port': pack_dict['payload']['payload']['dport'] if 'dport' in pack_dict['payload']['payload'] else None,
                'protocol': pack_dict['payload']['proto'] if 'proto' in pack_dict['payload'] else None,
                'ip_version': pack_dict['payload']['version']}
        if packet.haslayer(DNS) and pack_sum['dst_port'] == 53:
            pack_sum['dns_query'] = packet[DNSQR].qname.decode('utf-8') if packet.haslayer(DNSQR) else None
            pack_sum['dns_answer'] = packet[DNSRR].rdata.decode('utf-8') if packet.haslayer(DNSRR) else None
            if handle_dns(pack_sum['dns_query'], config):
                handle_error('dns', pack_sum['dns_query'], pack_sum)
        print(len(packets)+1, pack_sum)
        packets.append(pack_sum)
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
        
def get_hostname_from_ip(ip):
    try:  
        hostname, _, _ = socket.gethostbyaddr(ip)      
        return hostname
    except socket.herror:
        return None
    except Exception as e:
        return f"An error occurred: {e}"

def port_scan(host, start_port, end_port):
    for port in range(start_port, end_port+1):
        threading.Thread(target=scan_port, args=(host, port)).start()

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            print("Port {} is open".format(port))
        elif result == 10013:  # Connection refused
            print("Port {} is open but permission denied".format(port))
        sock.close()
    except:
        pass

def main(interval, packets_count, no_of_sessions=0):
    interface = interfaces.get_working_if()
    network = ipaddress.ip_network(f"{interface.ip}/24", strict=False)
    # host = 'localhost'
    # start_port = 1
    # end_port = 1000
    mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
    mongo_db = mongo_client["mydatabase"]
    mongo_col = mongo_db["devices"]
    packets = []
    log_file_path = "sniffer.log"
    config = get_config()
    filter = "tcp or udp or icmp"
    with open(log_file_path, "a") as log_file:
        try:
            while no_of_sessions != 0:
                sniff(iface=interface, filter=filter, prn=lambda pkt: handle_packet(pkt, network, packets, config, mongo_col), count=packets_count, store=0)
                no_of_sessions -= 1
            for packet in packets:
                log_file.write(f"{packet}\n")
            # json.dump(packets, log_file, indent=4)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            print(f"An error occurred: {e}")
    time.sleep(interval)

if __name__ == "__main__":
    interval = input("Enter the interval between sniffing packets sessions(in seconds): ")
    packets_count = input("Enter the number of packets to sniff on each session: ")
    no_of_sessions = input("Enter the number of sessions(0 for infinite): ")
    try: 
        interval = int(interval)
        packets_count = int(packets_count)
        no_of_sessions = int(no_of_sessions)
        if interval <= 0 or packets_count <= 0 or no_of_sessions < 0:
            raise ValueError("Interval and packets count must be positive integers.")
    except ValueError:
        print("Invalid input. Please enter integers for interval and packets count.")
        sys.exit(1)
    main(interval, packets_count, no_of_sessions)