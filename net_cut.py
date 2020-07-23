#Python 2
#sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
#sudo iptables --flush

import netfilterqueue

def procces_packet(packet):
    print(packet)
    packet.drop()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, procces_packet)
queue.run()