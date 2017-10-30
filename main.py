# -*- coding: utf-8 -*-
import socket
import struct
import time
import binascii


import os
#import textwrap
#seccion d03
decorador = "\t - "


def main():
    #conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    #conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    opc = 1
    eth_proto = 0
    ethertype = 0


    while True:
        os.system("clear")
        opc = int(input("1 - Paquetes ip\n2 - P aquetes arp\n--> "))
        print(str(type(opc)) +"  "+ str(opc))
        if opc == 3:
            exit()
        elif opc != 1 or opc != 2 :
            break
        
    while True:
        raw_data = conn.recvfrom(2048)

        if opc ==1 :
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data[0])
        else :
            ethernet_detailed = struct.unpack("!6s6s2s", raw_data[0][0:14])
            arp_header = raw_data[0][14:42]
            arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
            ethertype = ethernet_detailed[2]

        #raw_data, addr = conn.recvfrom(65535)
        #reducir
        #raw_data = conn.recvfrom(2048)
        #dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data[0])
        #eth_proto = 0
        #print("\nEthernet Frame")
        #print(("destino {}, origen {} ".format(dest_mac, src_mac)))
        #ethernet_detailed = struct.unpack("!6s6s2s", raw_data[0][0:14])
        #arp_header = raw_data[0][14:42]
        #arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
        #ethertype = ethernet_detailed[2]


        if eth_proto == 8:
            continue
            print((decorador + "Paquete IP"))
            (version, header_lenght, ttl, proto, src, target, data) = ipv4_packet(data)
            print((decorador + "version         " + str(version)))
            if proto == 1:
                print((decorador + "protocolo       icmp"))
            elif proto == 2:
                print((decorador + "protocolo       igmp"))
            elif proto == 6:
                print((decorador + "protocolo       tcp"))
            elif proto == 17:
                print((decorador + "protocolo       udp"))
            else:
                print((decorador + "protocolo       " + str(proto)))
            print((decorador + "IP origen       " + str(src)))
            print((decorador + "IP destino      " + str(target)))
            print((decorador + "ttl             " + str(ttl)))
        elif ethertype == '\x08\x06':
            print ("******************_ARP_HEADER_******************")
            #print ("Hardware type:   ", binascii.hexlify(arp_detailed[0]))
            print ("Protocolo    :   ", binascii.hexlify(arp_detailed[1]))
            #print ("Hardware size:   ", binascii.hexlify(arp_detailed[2]))
            #print ("Protocol size:   ", binascii.hexlify(arp_detailed[3]))
            #print ("Opcode:          ", binascii.hexlify(arp_detailed[4]))
            print ("Origen MAC   :   ", binascii.hexlify(arp_detailed[5]))
            print ("Origen IP    :   ", socket.inet_ntoa(arp_detailed[6]))
            print ("Destino MAC  :   ", binascii.hexlify(arp_detailed[7]))
            print ("Destino IP   :   ", socket.inet_ntoa(arp_detailed[8]))
            print ("*************************************************\n")
        else:
            
            continue
            print("\nEthernet Frame")
            print(("destino {}, origen {} ".format(dest_mac, src_mac)))
            print("Paquete no identificado")
            print("tipo "+str(eth_proto))
            #time.sleep(20)
        #time.sleep(5)


# 1 traducir el paquete python

def ethernet_frame(data):
    dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addres(dest_mac), get_mac_addres(source_mac), socket.htons(proto), data[14:]

# regresar mac  qq:ww:gr:sd:qw

def get_mac_addres(bytes_addr):
    #list para py3
    bytes_str = list(map('{:02x}'.format, bytes_addr))
    mac_addr = ":".join(bytes_str).upper()
    return mac_addr

#abrir el paquete ipv4


def ipv4_packet(data):
    version_header_lenght = data[0]
    version = version_header_lenght >> 4
    header_lenght = (version_header_lenght & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_lenght, ttl, proto, to_ip4(src), to_ip4(target), data[header_lenght:]

#convertir a formato ipv4 (decimal puteado)


def to_ip4(addr):
    return ".".join(map(str, addr))


####testing                        #####################
#paquetes icmp


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

#segmento tcp


def tcp_segment(data):
    (src_port, dest_port, sequence, aknowledgment, offset_reserved_flags) = struct.unpack("! H H L L H", data[14:])

    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, aknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
### en testing
main()