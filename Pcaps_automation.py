#!/usr/bin/python3

import pyshark
import os
import re
import pyfiglet
from tqdm import tqdm
from argparse import ArgumentParser
from tabulate import tabulate

def parser():
    parser = ArgumentParser()
    parser.add_argument('pcap', help="Select your file.pcap")
    parser.add_argument('--output', type=int, help="Enter output path")
    args = parser.parse_args()
    return args

path = parser().output
file = parser().pcap

pcap_file = pyshark.FileCapture(file, use_ek=True)

term_size = os.get_terminal_size()

def udp_stream(pcap):
    '''
    Printing all UDP data out of packets
    '''
    try:
        streams = set()
        for pkt in pcap:
            if ('ip' in pkt) and ('udp' in pkt):
                streams.add(pkt.udp.stream)
            elif ("IPV6" in pkt) and ('udp' in pkt):
                streams.add(pkt.udp.stream)
        strm_tup = tuple(streams)
        if len(strm_tup) == 0:
            print("No ip/udp or ipv6/udp found in pcap")
            pass
        else:
            f = open('udp_data.txt', 'w')
            x, y, z, k, l = [], [], [], [], []
            for i in tqdm(range(len(strm_tup))):
                for pkt in pcap:
                    if( 'ip' in pkt) and ('udp' in pkt) and pkt.udp.stream == i:
                        payload = pkt.udp.payload
                        x.append(payload)
                        layers = pkt.udp._layer_name + '_' + pkt.highest_layer #pkt[3]._layer_name
                        y.append(layers)
                        host = pkt.ip.addr
                        z.append(host)
                        version = pkt.ip.version
                        l.append(str(version)) 
                        port = pkt.udp.port
                        k.append(port)
                    elif ("IPV6" in pkt) and ('udp' in pkt) and pkt.udp.stream == i:
                        payload = pkt.udp.payload
                        x.append(payload)
                        layers = pkt.udp._layer_name + '_' + pkt.highest_layer #pkt[3]._layer_name
                        y.append(layers)
                        host = pkt.ipv6.addr
                        z.append(host)
                        version = pkt.ipv6.version
                        l.append(str(version))
                        port = pkt.udp.port
                        k.append(port)
                table = [(y[0], l[0], z[0], k[0])]
                head = ["Proto", "Version", "IPs", "Ports"]
                out = tabulate(table, headers=head, tablefmt="grid")
                pay = x[:]
                outline = u'\u2500' * term_size.columns
                f.write(f"{out} \n {pay} \n {outline} \n")
                x, y, z, k, l = [], [], [], [], []
            f.close
            print("udp_stream_data extracting is done")
    except:
        print("Error: udp_stream function is not working")

def tcp_stream(pcap):
    '''
    Printing all TCP data out of packets
    '''
    try:    
        streams = set()
        for pkt in pcap:
            if ('ip' in pkt) and ('tcp' in pkt) and pkt.tcp.has_field('payload'):
                streams.add(pkt.tcp.stream)
            elif ("IPV6" in pkt) and ('tcp' in pkt) and pkt.tcp.has_field('payload'):
                streams.add(pkt.tcp.stream)
    
        strm_tup = tuple(streams)
        if len(strm_tup) == 0:
            print("No ip/udp or ipv6/udp found in pcap")
            pass
        else:
            f = open('tcp_data.txt', 'w')
            x, y, z, k, l = [], [], [], [], []
            for i in tqdm(range(1,len(strm_tup))):
                for pkt in pcap:
                    if( 'ip' in pkt) and ('tcp' in pkt) and pkt.tcp.has_field('payload') and pkt.tcp.stream == i:
                        payload = pkt.tcp.payload
                        x.append(payload)
                        layers = pkt.tcp._layer_name + '_' + pkt.highest_layer
                        y.append(layers) 
                        host = pkt.ip.addr
                        z.append(host)
                        version = pkt.ip.version
                        l.append(str(version)) 
                        port = pkt.tcp.port
                        k.append(port)
                    elif ("IPV6" in pkt) and ('tcp' in pkt) and pkt.tcp.has_field('payload') and pkt.tcp.stream == i:
                        payload = pkt.tcp.payload
                        x.append(payload)
                        layers = pkt.tcp._layer_name + '_' + pkt.highest_layer
                        y.append(layers)
                        host = pkt.ipv6.addr
                        z.append(host)
                        version = pkt.ipv6.version
                        l.append(str(version))
                        port = pkt.tcp.port
                        k.append(port)
                table = [(y[0], l[0], z[0], k[0], strm_tup[i])]
                head = ["Proto", "Version", "IPs", "Ports", "Stream"]
                out = tabulate(table, headers=head, tablefmt="grid")
                pay = x[:]
                outline = u'\u2500' * term_size.columns
                f.write(f"{out} \n {pay} \n {outline} \n")
                x, y, z, k, l = [], [], [], [], []   
            f.close
            print("tcp_stream_data extracting is done")
    except:
        print("Error: tcp_stream function is not working")

def scr_dst_summary(pcap):
    '''
    The function asks one parameter to execute, and it will output all source and destination ip addresses with its occurrence of packets.
    ''' 
    
    try:
        print("Ipv4 extracting...")
        f = open("src_dst_summary.txt", 'w')
        ips = [pkt.ip.addr for pkt in pcap if 'ip' in pkt]
        if len(ips) == 0:
            print("Note: No IPv4 address in this pcap")
        else:
            protocol = [pkt.highest_layer for pkt in pcap if 'ip' in pkt]
            layers = [str(pkt.layers) for pkt in pcap if 'ip' in pkt]

            uniqeIps, uniqeProtocols, uniqeLayers = [], [], []
            for i in range(len(ips)):
                if ips[i] not in uniqeIps:
                    uniqeIps.append(ips[i])
                    uniqeProtocols.append(protocol[i])
                    uniqeLayers.append(layers[i])

            ipCount = []
            q = 0
            for uip in uniqeIps:
                for ip in ips:
                    if uip == ip:
                        q += 1
                ipCount.append(q)
                q = 0

            ports = []
            for ip in uniqeIps:
                for pkt in pcap:
                    if  'ip' in pkt and 'tcp' in pkt and pkt.ip.addr == ip:
                        x = []
                        x.append(tuple(pkt.tcp.port))
                    elif 'ip' in pkt and 'udp' in pkt and pkt.ip.addr == ip:
                        x = []
                        x.append(tuple(pkt.udp.port))
                    else:
                        pass
                ports.append(x)

            structured_uniqeLayers = [','.join(re.split(" Layer>, <| Layer>]|\[<", layer)[2:-1]) for layer in uniqeLayers]
            structured_uniqeIps = [' <-> '.join(ip) for ip in uniqeIps]
                
            finalRow = []
            for count, ip in tqdm(enumerate(structured_uniqeIps)):
                row = [ipCount[count], ip, structured_uniqeLayers[count], ports[count]]
                finalRow.append(row)
                
            titel_1 = '-'*114 + '\n'+' '*42 +'IPv4-Source/Destination Summary' + '\n'+'-'*114 
            head = ['Packets', 'Connections', 'Protocols', 'Ports']
            table_1 = tabulate(finalRow, headers=head, tablefmt="pretty")
            f.write(f"{titel_1}\n{table_1}\n")
            f.close
            print("Done\n")
    except:
        print("Error: something wrong in 'scr_dst_summary' function under IPv4 section.")

    try:
        print("Ipv6 extracting...")
        f_ = open("src_dst_summary.txt", 'a')
        ipv6s = [pkt.ipv6.addr for pkt in pcap if 'ipv6' in pkt]
        if len(ipv6s) == 0:
            print("Note: No Ipv6 address in this pcap")
        else:
            protocol = [pkt.highest_layer for pkt in pcap if 'ipv6' in pkt]
            layers = [str(pkt.layers) for pkt in pcap if 'ipv6' in pkt]

            uniqeIpv6s, uniqeProtocols, uniqeLayers = [], [], []
            for i in range(len(ipv6s)):
                if ipv6s[i] not in uniqeIpv6s:
                    uniqeIpv6s.append(ipv6s[i])
                    uniqeProtocols.append(protocol[i])
                    uniqeLayers.append(layers[i])

            ipv6Count = []
            q = 0
            for uipv6 in uniqeIpv6s:
                for ipv6 in ipv6s:
                    if uipv6 == ipv6:
                        q += 1
                ipv6Count.append(q)
                q = 0

            ports = []
            for ipv6 in uniqeIpv6s:
                for pkt in pcap:
                    if  'ipv6' in pkt and 'tcp' in pkt and pkt.ipv6.addr == ipv6:
                        x = []
                        x.append(tuple(pkt.tcp.port))
                    elif 'ipv6' in pkt and 'udp' in pkt and pkt.ipv6.addr == ipv6:
                        x = []
                        x.append(tuple(pkt.udp.port))
                    else:
                        pass
                ports.append(x)

            structured_uniqeLayers = [','.join(re.split(" Layer>, <| Layer>]|\[<", layer)[2:-1]) for layer in uniqeLayers]
            structured_uniqeIpv6s = [' <-> '.join(ipv6) for ipv6 in uniqeIpv6s]
                
            finalRow = []
            for count, ipv6 in tqdm(enumerate(structured_uniqeIpv6s)):
                row = [ipv6Count[count], ipv6, structured_uniqeLayers[count], ports[count]]
                finalRow.append(row)
                
            titel_2 = '-'*114 + ' \n'+' '*42 +'ipv6-Source/Destination Summary' + '\n'+'-'*114 
            head = ['Packets', 'Connections', 'Protocols', 'Ports']
            table_2 = tabulate(finalRow, headers=head, tablefmt="pretty")
            f_.write(f"{titel_2}\n{table_2}\n")
            f_.close
            (print("Done\n"))      
    except:
        print("Error: something wrong in 'scr_dst_summary' function under IPv6 section.")

layers = [str(pkt.layers) for pkt in pcap_file if 'ip' in pkt]
#structured_uniqeLayers = [','.join(re.split(" Layer>, <| Layer>]|\[<", layer)[2:-1]) for layer in layers]
y = []
for layer in layers:
    x = re.split(" Layer>, <| Layer>]|\[<", layer)
    for item in x:
        y.append(item)
convert_to_set = set(y)
protocols = tuple(convert_to_set)
    
ascii_banner = pyfiglet.figlet_format("Pcaps Automation")
print(ascii_banner, end='')
print("Authored by Thisara jeewantha")

request_for_start = f"\nDo you want to start analysing {file} (yes/no): "
request_for_tcp = f"Do you want to extract TCP stream data from {file} (yes/no): "
request_for_udp = f"Do you want to extract UDP stream data from {file} (yes/no): "

def get_userRequest(request):
    while True:
        possibleRequests_yes = ['y', 'yes', 'Y', 'YES', 'Yes']
        possibleRequests_no = ['n', 'no', 'N', 'NO', 'No']
        userRequest = input(request)
        if userRequest in possibleRequests_yes:
            return 1
            break
        elif userRequest in possibleRequests_no:
            return 0
            break
        else:
            print(f"{userRequest} is not acceptable so enter required input")
            continue

# if get_userRequest(request_for_start) == 0:
#     print("Exit, Bye-Bye!")

if get_userRequest(request_for_start) == 1:
    print("\nStarting Src and Dst addresses extraction...\n")
    scr_dst_summary(pcap_file)

    if 'TCP' in protocols :
        print("\nTCP protocol is found")
        if get_userRequest(request_for_tcp) == 1:
            print("Staring TCP stream data extraction...\n")
            tcp_stream(pcap_file)
        else:
            pass
    else:
        print("TCP is Not Found")

    if 'UDP' in protocols:
        print("\nUDP protocol is found")
        if get_userRequest(request_for_udp) == 1:
            print("Starting UDP stream data extraction...\n")
            udp_stream(pcap_file)
        else:
            pass
    else:
        print("UDP is Not Found")
    
else:
    print("Exit, Bye-Bye!")