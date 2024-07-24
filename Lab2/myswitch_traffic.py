'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *

MAC_info={}

MAX_NUM = 5

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while True:

        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return

        if MAC_info.get(eth.src) is None:
            if len(MAC_info) == MAX_NUM:
                MAC_del = ''
                MIN_volume = float('inf')
                for mac, info in list(MAC_info.items()):
                    if info['volume'] < MIN_volume:
                        MAC_del = mac
                        MIN_volume = info['volume']
                log_info (f"MAC address {MAC_del} has been removed.")
                del MAC_info[MAC_del]
            MAC_info[eth.src] = {'iface': fromIface, 'volume': 0}
        else:
            if MAC_info[eth.src]['iface'] != fromIface:
                MAC_info[eth.src]['iface'] = fromIface

        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if MAC_info.get(eth.dst) is not None:
                log_info(f"(sending)Flooding packet {packet} to {MAC_info[eth.dst]['iface']}")
                net.send_packet(MAC_info[eth.dst]['iface'], packet)
                MAC_info[eth.dst]['volume'] += 1
            else:
                for intf in my_interfaces:
                    if fromIface != intf.name:
                        log_info(f"(broadcast)Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
    net.shutdown()
