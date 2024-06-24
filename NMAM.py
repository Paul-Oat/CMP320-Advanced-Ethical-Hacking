

import argparse
import nmap
import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import ARP, Ether, srp
import pyshark
from twilio.rest import Client

#change me Twilio and Interface values 
account_sid = "AC******************************"
auth_token = "c********************************"
TW_Number = "+44**********"
DEST_Num = "+44**********"
INTERFACE_CAP = "Wi-Fi"
#####

#sms function
def sms_Mesage():
  client = Client(account_sid, auth_token)
  message = client.messages.create(
    body="A device has exceeded the threshold",
    from_= TW_Number,
    to= DEST_Num
  )
  print(message.sid)

#data usage
def dataUsage(threshold, interface):
 
 #start the capture and initalse the devoce 
    devices = {} 
    capture = pyshark.LiveCapture(interface)
    #begin packet sniffing 
    for packet in capture.sniff_continuously():
     #search ip 
        if 'ip' in packet:
            # get src and dst ip's
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            #add to or count up packet length from src
            if src_ip in devices:
                devices[src_ip] += int(packet.length)
            else:
                devices[src_ip] = int(packet.length)
            #add to or count up packet length from dst 
            if dst_ip in devices:
                devices[dst_ip] += int(packet.length)
            else:
                devices[dst_ip] = int(packet.length)
                #check if any devoce has breached threshold
            for device in devices:

                if int(devices[device]) > int(threshold):
                    #print and call message system
                    print(f"Device {device} has exceeded the threshold ({threshold} bytes).")
                    sms_Mesage()
                    #end the monitor
                    break




#device scan
def scan_Device(addr):
    # add to graph
    Graph.add_node(addr)
    nm = nmap.PortScanner()
    # check open ports and log  #nmap scon with the os and service version 
    nm.scan(hosts=addr, arguments='-O -sV')
    #tcp connections 
    if 'tcp' in nm[addr]:
        for port in nm[addr]['tcp']:
            if nm[addr]['tcp'][port]['state'] == 'open':
                #add the open ports to the device 
                Graph.nodes[addr]['open_ports'] = Graph.nodes[addr].get('open_ports', []) + [port]
                #if os matches add to graph 
        if 'osmatch' in nm[addr]:
            os_matches = nm[addr]['osmatch']
            if os_matches:
                Graph.nodes[addr]['os'] = os_matches[0]['name']
                #quick list scan to check if device is up and plot on graph 
     
    else:
        print("device added but no information given")  # if device is unresponsive 


# art headder
art_head = """
        ███    ██    ███    ███     █████     ███    ███ 
        ████   ██    ████  ████    ██   ██    ████  ████ 
        ██ ██  ██    ██ ████ ██    ███████    ██ ████ ██ 
        ██  ██ ██    ██  ██  ██    ██   ██    ██  ██  ██ 
        ██   ████ ██ ██      ██ ██ ██   ██ ██ ██      ██ 
        Network      Map           And        Monitor
        By Paul Oates 
        """
# display grphic 
print(art_head)
# Initialize the argument parser
parser = argparse.ArgumentParser(description='Network Monitoring Tool')


parser.add_argument('-m', '--map', action='store_true', help='Map the network')
parser.add_argument('-b', '--bytes', type=str, help='Monitor data usage. limit in bytes')
parser.add_argument('-s', '--subnet', type=str, help='Subnet to scan. Required', required="True")

# Parse the arguments
args = parser.parse_args()

# Check which options the user selected
if args.map:
    print('Mapping the network...')
    Graph = nx.Graph()
    #call map function
     # use an arp scan to identify devices on network 
    arp = ARP(pdst=args.subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    Devices = []
    host = [] 

 
#for devices in result scan with nmap 
    for sent, received in result:
        Devices.append({'IP': received.psrc})
    for Device in Devices:
        scan_Device(Device['IP'])
    pos = nx.spring_layout(Graph)

    #add device labels
    node_labels = {
    node: f'{node}\n{Graph.nodes[node].get("os", "")}\n{Graph.nodes[node].get("device_type", "")}\nOpen Ports: {", ".join(str(port) for port in Graph.nodes[node].get("open_ports", []))}'
    for node in Graph.nodes()
}
    #plot graph colour red 
    nx.draw_networkx_nodes(Graph, pos, node_size=500, node_color='red')
    nx.draw_networkx_edges(Graph, pos, width=1, alpha=0.5)
    nx.draw_networkx_labels(Graph, pos, labels=node_labels, font_size=8)
    #disable axis 
    plt.axis('off')
    #set map size 
    plt.figure(figsize=(20, 20))
    plt.savefig('map.png')
    # Draw the graph
    print(Graph.nodes)
    print(Graph.edges(data=True))

if args.bytes:
    print('data usage limit set {args.bytes}')
    #  monitor function
    dataUsage(args.bytes, INTERFACE_CAP)  
#goodbye message 
print("exiting program, Goodbye")









   

