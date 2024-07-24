#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from collections import deque
import os

class Entry():
    def __init__(self, packet, seqNum):
        self.packet = packet
        self.isACK = False
        self.seqNum = seqNum
        self.resendNum = 0

class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):

        self.net = net
        self.Intf = net.interface_by_name('blaster-eth0')
        self.blasteeIp = blasteeIp
        self.num = int(num)
        self.payloadLength = int(length)
        self.timeout = float(timeout)
        self.recvTimeout = float(recvTimeout)
        self.limit = int(senderWindow)
        self.middlboxEth = EthAddr('40:00:00:00:00:01')
        self.timestamp = -1
        self.sendqueue = []
        self.recvqueue = []
        self.lastsendtime = 0
        self.lastrecvtime = 0
        self.nxtnum = 1

        self.lastsendIdx = 0
        self.sendWindow = deque(maxlen=self.limit)
        self.firstpacketTime = -1
        self.lastACKdTime = 0
        self.reTX = 0
        self.coarseTOs = 0
        self.Throughput = 0
        self.Goodput = 0

    def create_packet(self, seqNum):
        eth = Ethernet()
        eth.src = self.Intf.ethaddr
        eth.dst = self.middlboxEth

        ip = IPv4(protocol = IPProtocol.UDP)
        ip.src = self.Intf.ipaddr
        ip.dst = self.blasteeIp

        udp = UDP()
        pkt = eth + ip + udp + seqNum.to_bytes(4, 'big') + self.payloadLength.to_bytes(2, 'big') + os.urandom(self.payloadLength)
        return pkt

    def check_shutdown(self):
        if self.num != 0:
            return False
        for entry in self.sendWindow:
            if entry.isACK == False:
                return False

        totalTXtime = self.lastACKdTime - self.firstpacketTime

        print("\n-----------------------------------------------------\n")
        print(f"Total TX time (in seconds): {totalTXtime}")
        print(f"Number of reTX: {self.reTX}")
        print(f"Number of coarse TOs: {self.coarseTOs}")
        print(f"Throughput (Bps): {self.Throughput * self.payloadLength / totalTXtime}")
        print(f"Goodput (Bps): {self.Goodput * self.payloadLength / totalTXtime}")
        print("\n-----------------------------------------------------\n")
        return True

    def send_pkt(self):
        curTime = time.time() #save time now ,do not use time.time() in for currsion
        if curTime - self.recvTimeout / 1000 > self.lastsendtime:
            if len(self.sendqueue) != 0:    
                entry = self.sendqueue.pop(0)
                packet = entry.packet
                self.lastsendtime = curTime
                self.Throughput += 1
                if entry.resendNum == 0:
                    self.Goodput += 1
                    print("send", entry.seqNum)
                else:
                    self.reTX += 1
                    print("resend", entry.seqNum)

                if self.firstpacketTime == -1:
                    self.firstpacketTime = time.time()
                self.net.send_packet(self.Intf.name, packet)

            else:
                update = 0
                while len(self.sendWindow) and self.sendWindow[0].isACK == True:
                    print("pop", self.sendWindow[0].seqNum)
                    self.sendWindow.popleft()
                    self.timestamp = time.time()
                    update = 1
                if self.timestamp == -1:
                    self.timestamp = time.time()
                    update = 1

                curTime = time.time()

                while self.num != 0 and len(self.sendWindow) < self.limit:
                    nxt = self.nxtnum
                    self.nxtnum += 1
                    packet = self.create_packet(nxt)
                    entry = Entry(packet, nxt)
                    print("append", entry.seqNum)
                    self.sendWindow.append(entry)
                    self.num -= 1   
                if update:
                    for entry in self.sendWindow:
                        if entry.isACK == True:
                            continue
                        entry.resendNum = 0
                        self.sendqueue.append(entry)
                elif curTime - self.timestamp > self.timeout:
                    self.timestamp = time.time()
                    self.coarseTOs += 1 
                    for entry in self.sendWindow:
                        if entry.isACK == True:
                            continue
                        entry.resendNum = 1
                        self.sendqueue.append(entry)
                    
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        #print("I got a packet")
        Raw = packet.get_header(RawPacketContents)
        seqNum = int.from_bytes(Raw.data[:4], 'big')
        for i, entry in enumerate(self.sendWindow):
            if entry.seqNum == seqNum:
                self.lastACKdTime = max(self.lastACKdTime, time.time())
                print("ACK", seqNum)
                entry.isACK = True
                #self.update()
                break

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            if time.time() - self.recvTimeout / 1000 > self.lastrecvtime:
                if len(self.recvqueue) != 0:
                    self.lastrecvtime = time.time()
                    recv = self.recvqueue.pop(0)
                    self.handle_packet(recv)

            if self.check_shutdown():
                print("mission clear")
                break

            self.send_pkt()
            try:
                recv = self.net.recv_packet(timeout = self.recvTimeout / 1000)
            except NoPackets:
                #self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.recvqueue.append(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
