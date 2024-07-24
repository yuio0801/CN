#!/usr/bin/env python3

import time
import threading
from random import randint
import random

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        self.intf1 = "middlebox-eth0"
        self.intf2 = "middlebox-eth1"
        self.my_interfaces = [self.net.interface_by_name(self.intf1), self.net.interface_by_name(self.intf2)]
        self.mymacs = [intf.ethaddr for intf in self.my_interfaces]
        self.myip = [intf.ipaddr for intf in self.my_interfaces]
        print("\n------------------------\n")
        print(self.mymacs[0], self.mymacs[1])
        print("\n------------------------\n")


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == self.intf1:
            print("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if random.random() <= self.dropRate:
                return

            packet[Ethernet].src = self.mymacs[0]
            packet[Ethernet].dst = self.mymacs[1]

            self.net.send_packet(self.intf2, packet)
            #self.net.send_packet("middlebox-eth1", packet)

        elif fromIface == "middlebox-eth1":
            print("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''

            packet[Ethernet].src = self.mymacs[1]
            packet[Ethernet].dst = self.mymacs[0]

            self.net.send_packet(self.intf1, packet)
        else:
            print("Oops :))")

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
