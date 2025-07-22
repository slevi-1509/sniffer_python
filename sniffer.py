import sys
# from scapy.all import *
from scapy.all import scapy, DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP
import json
import time
from time import ctime
import os

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
        
def handle_packet(packet, log, packets, config):
    try:
        pkt_time = ctime(packet.time)
        pack_dict = json.loads(packet.json())
        # print(packet.payload.layers())
        pack_sum = {'timestamp': pkt_time,
                    'dst_mac': pack_dict['dst'], 
                    'src_mac': pack_dict['src'], 
                    'dst_ip': pack_dict['payload']['dst'], 
                    'src_ip': pack_dict['payload']['src'],
                    'dst_port': pack_dict['payload']['payload']['dport'],
                    'src_port': pack_dict['payload']['payload']['sport'],
                    'protocol': pack_dict['payload']['proto'] if 'proto' in pack_dict['payload'] else None,
                    'ip_version': pack_dict['payload']['version']}
        if packet.haslayer(DNS) and pack_sum['dst_port'] == 53:
            pack_sum['dns_query'] = packet[DNSQR].qname.decode('utf-8') if packet.haslayer(DNSQR) else None
            pack_sum['dns_answer'] = packet[DNSRR].rdata.decode('utf-8') if packet.haslayer(DNSRR) else None
            if handle_dns(pack_sum['dns_query'], config):
                handle_error('dns', pack_sum['dns_query'], pack_sum)
        print(pack_sum)
        packets.append(pack_sum)
    except KeyboardInterrupt:
                sys.exit(0)
        
def handle_dns(url, config):
    for entry in config['url']:
        # print(entry)
        # print(url)
        # print(str(url).find(str(entry)))
        if str(url).find(str(entry)) != -1:
            # handle_error('dns')
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

def main(interface, interval, packets_count):
    packets = []
    log_file_path = "sniffer_log.json"
    config = get_config()
    filter = "tcp or udp or icmp"
    # filter = "(tcp or udp) and port 53"
    while True:
        with open(log_file_path, "w") as log_file:
            try:
                sniff(iface=interface, filter=filter, prn=lambda pkt: handle_packet(pkt, log_file, packets, config), count=packets_count, store=0)
                json.dump(packets, log_file, indent=4)
            except KeyboardInterrupt:
                log_file.close()
                sys.exit(0)
        time.sleep(interval)

if __name__ == "__main__":
    interface = scapy.interfaces.get_working_if()
    # interval = input("Enter the interval between sniffing packets (in seconds): ")
    # packets_count = input("Enter the number of packets to sniff on each session: ")
    # try: 
    #     interval = int(interval)
    #     packets_count = int(packets_count)
    #     if interval <= 0 or packets_count <= 0:
    #         raise ValueError("Interval and packets count must be positive integers.")
    # except ValueError:
    #     print("Invalid input. Please enter integers for interval and packets count.")
    #     sys.exit(1)
    main(interface, 1, 100)