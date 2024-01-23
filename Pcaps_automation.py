#!/usr/bin/python3

import pyshark
import os
from tqdm import tqdm
from argparse import ArgumentParser
from tabulate import tabulate


def parser():
    parser = ArgumentParser()
    parser.add_argument('pcap', help="Select your file.pcap")
    parser.add_argument('--output', type=int, help="Enter output path")
    args = parser.parse_args()
    return args

file = parser().pcap
path = parser().output

pcap_file = pyshark.FileCapture(parser().pcap, use_ek=True)

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


try:
    print("tcp_stream_data is extracting...")
    tcp_stream(pcap_file)
except:
    print("Errooooo")

try:
    print("udp_stream_data is extracting...")
    udp_stream(pcap_file)
    
except:
    print("Errooooo")




