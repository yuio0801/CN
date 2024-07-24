#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        self.blasterIp = blasterIp
        self.num = num

        self.my_interfaces = self.net.interfaces()
        self.mymacs = [intf.ethaddr for intf in self.my_interfaces]
        self.Intf = self.net.interface_by_name('blastee-eth0')

    def creat_ACK_packet(self, ethSrc, ethDst, ipSrc, ipDst, seqNum, payload):
        eth = Ethernet()
        eth.src, eth.dst = ethSrc, ethDst

        ip = IPv4(protocol = IPProtocol.UDP)
        ip.src, ip.dst = ipSrc, ipDst
        ip.ttl = 64

        udp = UDP()

        ACK_packet = eth + ip + udp + seqNum.to_bytes(4, 'big') + payload

        return ACK_packet

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        print(f"I got a packet from {fromIface}")
        print(f"Pkt: {packet}")

        if packet[Ethernet].ethertype != EtherType.IPv4 or not packet.has_header(IPv4) or not packet.has_header(UDP):
            return

        Raw = packet.get_header(RawPacketContents)
        seqNum = int.from_bytes(Raw.data[:4], 'big')
        payload = Raw.data[6:]

        if len(payload) < 8:
            payload += "\0".encode() * (8 - len(payload))
        payload = payload[0:8]

        ACK_packet = self.creat_ACK_packet(
            self.Intf.ethaddr,
            '40:00:00:00:00:02',
            self.Intf.ipaddr,
            self.blasterIp,
            seqNum,
            payload
        )

        print("sendACK",seqNum)
        self.net.send_packet(self.Intf, ACK_packet)

    def start(self):
        '''A running daemon of the blastee.
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
    blastee = Blastee(net, **kwargs)
    blastee.start()
