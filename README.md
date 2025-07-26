Sniffer application with python (For Raspberry Pi-5 as an Access-Point):
using Scapy library for capturing packet.
using MongoDB for devices divcovered on the local network.

configuration file (sniffer.conf) contain the lists of anomalies to capture.
for now it's a 'url' list of strings the are part of a DNS addresses.

On load, application detect the active network connection and assign all capturing to it,
and user required to enter 3 inputs:
  * interval: pause time in seconds between sniffing sessions.
  * packets_count: number of packets to capture in each session.
  * no_of_sessions: number of sessions to run.

Every packet is checked for:

* source device information: 

  If the source mac address is not found in DB and the ip address belong to the local network,
  2 checks will run on the device IP:
  * an attempt to get the host name of the device.
  * an active scan for open system ports (0 - 1023) using threading.
  all the collected device information will be stored on MongoDB.

  If the source mac address found in DB and the new ip address is different, the document will be updated.
  
* DNS Requsets:  

  If a DNS layer exists and destination port is 53 (DNS Protocol),
  the DNS query is compare to the 'url' list in the configuration file. (thr DNS query contain the 'url' string).
  if True, a record is created in sniffer_errors.log file, with added information of the DNS. 

After packet checks, a record is created for every packet with the necessary information and added to the packets list.
When all sessions are done, the complete packets list is added to the sniffer.log file.




  
