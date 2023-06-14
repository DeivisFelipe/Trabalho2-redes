import os 
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.all import sr1, send, sniff, Raw

ip_src = '10.1.1.1'
ip_dst = '10.1.1.2'
dst_port = 8881
timeout = 0.150
MSS = 1460

ip_pkt = IP(src=ip_src, dst=ip_dst)

def begin_connection():
    """Begin connection using the three-way handshake algorithm."""

    syn_pkt = ip_pkt / TCP(dport=dst_port, flags='S', seq=8000)
    while True:
        answer = sr1(syn_pkt, timeout=timeout)
        if answer is not None:
            break

    seq = answer[TCP].ack
    ack = answer[TCP].seq + 1

    ack_pkt = ip_pkt / TCP(dport=dst_port, flags='A', seq=seq, ack=ack)
    send(ack_pkt)

    return seq, ack

def end_connection(seq, ack):
    """End connection using three-way handshake algorithm."""

    fin_pkt = ip_pkt / TCP(dport=dst_port, flags='FA', seq=seq, ack=ack)
    while True:
        response = sr1(fin_pkt)
        if response is not None:
            break
    ack_pkt = ip_pkt / TCP(dport=dst_port, flags='A', seq=response[TCP].ack, ack=response[TCP].seq + 1)
    send(ack_pkt)

def send_pkt(pkt, file, curr_file_position):
    file.seek(curr_file_position)
    data = file.read(MSS)
    send(pkt / data)

def sr1_pkt(pkt, file, curr_file_position, timeout):
    file.seek(curr_file_position)
    data = file.read(MSS)
    while True:
        response = sr1(pkt / data, timeout=timeout)
        if response is not None:
            return response[TCP].ack

def send_data(file, file_size, pkt, timeout):
    pkts_to_send = 2
    curr_file_position = 0
    while True:
        for _ in range(pkts_to_send - 1):
            send_pkt(pkt, file, curr_file_position)
            pkt.seq = pkt.seq + MSS
            curr_file_position = curr_file_position + MSS
        ack = sr1_pkt(pkt, file, curr_file_position, timeout)
        if ack != pkt.seq + MSS:
            curr_file_position = curr_file_position - (pkt.seq - ack)
        else:
            curr_file_position = curr_file_position + MSS
        pkt.seq = ack
    return pkt.seq, pkt.ack
    
def main():
    seq, ack = begin_connection()
    f = open("lotr.txt", "rb")
    pkt = ip_pkt / TCP(dport=dst_port, flags='PA', seq=seq, ack=ack)
    seq, ack = send_data(f, os.path.getsize("lotr.txt"), pkt, timeout)
    end_connection(seq, ack)

if __name__ == '__main__':
    main()
