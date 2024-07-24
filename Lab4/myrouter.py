#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

max_length = 20
ARP_TABLE_TIME_OUT = 10000
ARP_TIME_OUT = 1
MAX_TRY = 5

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.my_interfaces = net.interfaces()
        self.mymacs = [intf.ethaddr for intf in self.my_interfaces]
        self.myip = [intf.ipaddr for intf in self.my_interfaces]
        self.myintfname = [intf.name for intf in self.my_interfaces]
        self.Arp_table = {}
        self.forwarding_table = []
        self.packet_queue = {}
        self.arp_dict = {}

        with open('forwarding_table.txt', 'r') as file:
            for line in file:
                network_address, subnet_mask, next_hop_address, interface = line.strip().split()
                self.forwarding_table.append((IPv4Address(network_address), IPv4Address(subnet_mask), IPv4Address(next_hop_address), interface))
        for intf in self.my_interfaces:
            self.forwarding_table.append((IPv4Address(int(intf.netmask) & int(intf.ipaddr)), intf.netmask, None, intf.name))
        print("")
        self.print_fib_table()
        # other initialization stuff here

    def print_arp_table(self):
        print("Arp table")
        print("---------------------------------------------------------------------------")
        print(f"IP{'':<{max_length}}MAC{'':<{max_length}}LastUpdTime{'':<{max_length}}")
        for ip, info in list(self.Arp_table.items()):
            print(f"{str(ip):<{max_length}}  {str(info['MAC']):<{max_length}}   {str(info['timestamp']):<{max_length}}")
        print("---------------------------------------------------------------------------")

    def print_fib_table(self):
        print("forwarding talbe")
        print("---------------------------------------------------------------------------")
        print(f"IP{'':<{max_length}}mask{'':<{max_length}}nexthop{'':<{max_length}}intf{'':<{max_length}}")
        for network_address, subnet_mask, next_hop_address, interface in self.forwarding_table:
            print(f"{str(network_address):<{max_length}}{str(subnet_mask):<{max_length}}{str(next_hop_address):<{max_length}}{interface:<{max_length}}")
        print("---------------------------------------------------------------------------")

    def prefix_match(self, destaddr):
        max_len = 0
        ret = None
        for entry in self.forwarding_table:
            network_address, subnet_mask, next_hop_address, interface = entry
            prefixnet = IPv4Network(str(network_address) + '/' + str(subnet_mask))
            # same as IPv4Network('172.16.0.0/255.255.0.0')
            #print(prefixnet, destaddr)
            if destaddr in prefixnet:
                if prefixnet.prefixlen > max_len:
                    max_len = prefixnet.prefixlen
                    ret = entry
        return ret

    def send_packet_inqueue(self, find_dstip, find_dsthw):
        if self.packet_queue.get(find_dstip) is None:
            return
        queue = self.packet_queue[find_dstip]
        for Oface, packet in queue:
            if packet.has_header(IPv4):
                eth_header = packet.get_header(Ethernet)
                eth_header.dst = find_dsthw
                eth_header.src = Oface.ethaddr
                packet[0] = eth_header
                self.net.send_packet(Oface, packet)
            else:
                self.net.send_packet(Oface, packet)
        del self.packet_queue[find_dstip]

    def forwarding(self, packet):
        IPv4_header = packet.get_header(IPv4)
        entry = self.prefix_match(IPv4_header.dst)
        network_address, subnet_mask, next_hop_address, interface = entry
        
        Oface = self.net.interface_by_name(interface) 
        eth_header = packet.get_header(Ethernet)

        if next_hop_address is None:
            if self.Arp_table.get(IPv4_header.dst) is None:
                arp_request_packet = create_ip_arp_request(Oface.ethaddr, Oface.ipaddr, IPv4_header.dst)
                if self.arp_dict.get(IPv4_header.dst) is None:
                    self.arp_dict[IPv4_header.dst] = {'trytime': 1, 'timestamp': time.time(), 'intf': Oface, 'packet': arp_request_packet}
                    self.net.send_packet(Oface, arp_request_packet)
                    self.packet_queue[IPv4_header.dst] = [(Oface, packet)]
                else:
                    if self.packet_queue.get(IPv4_header.dst):
                        self.packet_queue[IPv4_header.dst].append((Oface, packet))
                    else:
                        self.packet_queue[IPv4_header.dst] = [(Oface, packet)]
            else:
                eth_header.dst = self.Arp_table[IPv4_header.dst]['MAC']
                eth_header.src = Oface.ethaddr
                packet[0] = eth_header
                self.net.send_packet(Oface, packet)
        else:
            if self.Arp_table.get(next_hop_address) is None:
                arp_request_packet = create_ip_arp_request(Oface.ethaddr, Oface.ipaddr, next_hop_address)
                if self.arp_dict.get(next_hop_address) is None:
                    self.arp_dict[next_hop_address] = {'trytime': 1, 'timestamp': time.time(), 'intf': Oface, 'packet': arp_request_packet}
                    self.net.send_packet(Oface, arp_request_packet)
                    self.packet_queue[next_hop_address] = [(Oface, packet)]
                else:
                    if self.packet_queue.get(next_hop_address):
                        self.packet_queue[next_hop_address].append((Oface, packet))
                    else:
                        self.packet_queue[next_hop_address] = [(Oface, packet)]
            else:
                eth_header.dst = self.Arp_table[next_hop_address]['MAC']
                eth_header.src = Oface.ethaddr
                packet[0] = eth_header
                self.net.send_packet(Oface, packet)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        Iface = self.net.interface_by_name(ifaceName)

        Ethernet_header = packet.get_header(Ethernet)
        if str(Ethernet_header.dst) != 'ff:ff:ff:ff:ff:ff' and Ethernet_header.dst != Iface.ethaddr:
            #drop
            return 
        
        if packet.has_header(Arp):
            ARP_header = packet.get_header(Arp)
            if packet.num_headers() != 2:
                return 

            srchw = ARP_header.senderhwaddr
            srcip = ARP_header.senderprotoaddr
            dsthw = ARP_header.targethwaddr
            dstip = ARP_header.targetprotoaddr

            Ask_Intf = None
            for Intf in self.my_interfaces:
                if dstip == Intf.ipaddr:
                    Ask_Intf = Intf
                    break
            if Ask_Intf is None:
                #arp not for router, drop
                return


            if ARP_header.operation == ArpOperation.Request:
                arp_reply_packet = create_ip_arp_reply(Ask_Intf.ethaddr, srchw, dstip, srcip)
                if self.packet_queue.get(srcip):
                    self.packet_queue[srcip].append((Iface, arp_reply_packet))
                else:
                    self.packet_queue[srcip] = [(Iface, arp_reply_packet)]
            
            if not (ARP_header.operation == ArpOperation.Reply and str(srchw) == 'ff:ff:ff:ff:ff:ff'):
                self.Arp_table[srcip] = {'MAC': srchw, 'timestamp': time.time()}
                print("")
                self.print_arp_table()

            if self.Arp_table.get(srcip) is not None:
                self.send_packet_inqueue(srcip, srchw)
                if self.arp_dict.get(srcip) is not None:
                    del self.arp_dict[srcip]

        elif packet.has_header(IPv4):
            IPv4_header = packet.get_header(IPv4)
            if IPv4_header.dst in self.myip:
                #for router, teckle in Lab5
                #assert False
                return
            else:
                IPv4_header.ttl -= 1
                if IPv4_header.ttl == 0:
                    #teckle in Lab5
                    #assert False
                    return 
            
            #find minimax prefix
            
            entry = self.prefix_match(IPv4_header.dst)
            if entry is None:
                #not match, teckle in Lab5
                return 
            
            self.forwarding(packet)

    def update(self):
        for ip, info in list(self.Arp_table.items()):
            if time.time() - info['timestamp'] > ARP_TABLE_TIME_OUT:
                print(f"Arptable {ip} has timed out.")
                del self.Arp_table[ip] 
                print("")  
                self.print_arp_table()
        
        for dstip, info in list(self.arp_dict.items()):
            trytime, timestamp, packet, Oface = info['trytime'], info['timestamp'], info['packet'], info['intf']
            if trytime == MAX_TRY and time.time() - timestamp >= ARP_TIME_OUT:
                del self.packet_queue[dstip]
                del self.arp_dict[dstip]
            elif trytime < MAX_TRY and time.time() - timestamp >= ARP_TIME_OUT:
                self.arp_dict[dstip] = {'trytime': trytime + 1, 'timestamp': time.time(), 'intf': Oface, 'packet': packet}
                self.net.send_packet(Oface, packet)

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        #build forwarding table
        tim = time.time()
        while True:
            '''if time.time() - tim > 30:
                break'''
            self.update()
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            
            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
