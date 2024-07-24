'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
import time

MAC_info={}

TIME_OUT = 10

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

        for mac, info in list(MAC_info.items()):
            if time.time() - info['timestamp'] > TIME_OUT:
                log_info (f"MAC address {mac} has timed out.")
                del MAC_info[mac]

        if MAC_info.get(eth.src) is None:
            MAC_info[eth.src] = {'iface': fromIface, 'timestamp': time.time()}
        else:
            if MAC_info[eth.src]['iface'] != fromIface:
                MAC_info[eth.src]['iface'] = fromIface
            MAC_info[eth.src]['timestamp'] = time.time() 

        

        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if MAC_info.get(eth.dst) is not None:
                log_info(f"(sending)Flooding packet {packet} to {MAC_info[eth.dst]['iface']}")
                net.send_packet(MAC_info[eth.dst]['iface'], packet)
            else:
                for intf in my_interfaces:
                    if fromIface != intf.name:
                        log_info(f"(broadcast)Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
    net.shutdown()
