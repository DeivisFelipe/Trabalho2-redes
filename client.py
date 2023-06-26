import math
import os
import time

from matplotlib import pyplot as plt
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import IP, TCP
from scapy.all import sr1, send, sr, AsyncSniffer
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff

ip_src = '10.1.1.1'
ip_dst = '10.1.1.2'
dst_port = 8881
timeout = 0.15
# Maximum Segment Size
MSS = 1460

ip_pkt = IP(src=ip_src, dst=ip_dst)

received_acks = {}

results = []


# Função para enviar o pacote de conexão
def begin_connection():
    """Begin connection using the three-way handshake algorithm."""

    # Bota o pacote TCP dentro de um IP
    syn_pkt = ip_pkt / TCP(dport=dst_port, flags='S', seq=8000)

    # While para enviar o pacote de conexão até receber algo
    while True:
        # Enviar o pacote e esperar a resposta
        answer = sr1(syn_pkt, timeout=timeout)
        # Se a resposta não for nula, para o loop
        if answer is not None:
            break

    # Pegar o número de sequência e de ack da resposta
    seq = answer[TCP].ack
    ack = answer[TCP].seq + 1

    # Enviar o ACK
    ack_pkt = ip_pkt / TCP(dport=dst_port, flags='A', seq=seq, ack=ack)
    # Enviar o pacote
    send(ack_pkt)

    return seq, ack


# Função para enviar o pacote de finalização
def end_connection(seq, ack):
    """End connection using three-way handshake algorithm."""

    # Enviar o pacote de finalização
    fin_pkt = ip_pkt / TCP(dport=dst_port, flags='FA', seq=seq, ack=ack)

    # Enviar o pacote até receber uma resposta
    while True:
        response = sr1(fin_pkt)
        if response is not None:
            break

    # Enviar o ACK
    ack_pkt = ip_pkt / TCP(dport=dst_port, flags='A', seq=response[TCP].ack, ack=response[TCP].seq + 1)
    send(ack_pkt)


# Função para enviar o pacote de dados e receber a confirmação
def sr_pkt(pkts, rtt):
    t = rtt * (1 + math.log10(len(pkts)))
    # print(rtt, t)
    respondidos, nao_respondidos = sr(pkts, timeout=t, verbose=False)
    return respondidos, nao_respondidos


def CriaPacote(seq, ack, data=b''):
    return ip_pkt / TCP(dport=dst_port, flags='PA', seq=seq, ack=ack) / data


def SS(cwind, ss_thresh):
    cwind = cwind * 2
    return cwind, ss_thresh


def AI(cwind, ss_thresh):
    cwind = cwind + 1
    return cwind, ss_thresh


def MD(cwind, ss_thresh):
    ss_thresh = cwind // 2
    if ss_thresh < 2:
        ss_thresh = 2
    cwind = ss_thresh
    return cwind, ss_thresh


def isAtSlowStart(cwind, ss_thresh):
    return cwind < ss_thresh


def send_data(file, file_size, pkt, rtt):
    curr_file_position = 0
    curr_file_position_confirmed = 0
    last_ack = pkt.seq
    ss_thresh = 16
    cwind = 1
    RTT = rtt

    # print(curr_file_position_confirmed, curr_file_position, file_size)

    ack_to_file_position_and_time = {}

    # Enquanto a posição atual do arquivo for menor que o tamanho do arquivo
    while curr_file_position_confirmed < file_size:
        listaDePacotes = []
        # For para enviar os pacotes considerando o numero de pacotes que podem ser enviados
        for _ in range(cwind):
            # Faz o seek no arquivo
            file.seek(curr_file_position)
            # Cria o pacote
            var = file.read(MSS)
            if var == b'':
                break
            novopkt = CriaPacote(pkt.seq, pkt.ack, var)
            # Adiciona o pacote na lista de pacotes
            listaDePacotes.append(novopkt)
            ack_to_file_position_and_time[novopkt.seq + len(var)] = (curr_file_position + len(var), time.time())

            # Atualiza o numero de sequencia do pacote
            pkt.seq = pkt.seq + len(var)

            # Atualiza a posição atual do arquivo não confirmada
            curr_file_position += len(var)

        # Envia os pacotes
        answered, unanswered = sr_pkt(listaDePacotes, RTT)
        # Ve se algum dos pacotes respondidos é o pacote de confirmação
        for response in answered:
            if response[1].ack > last_ack:
                last_ack = response[1].ack
            # print(response[1].ack, last_ack)

        if len(answered) == 0:  # timeout
            cwind, ss_thresh = MD(cwind, ss_thresh)
            cwind = 1

            if not len(received_acks) == 0:
                biggest_ack = max(received_acks)
                if biggest_ack > last_ack:
                    last_ack = biggest_ack
                    curr_file_position_confirmed = ack_to_file_position_and_time[last_ack][0]

            curr_file_position = curr_file_position_confirmed
            pkt.seq = last_ack
            # print("timeout")
        elif last_ack != pkt.seq:  # Se o ack for diferente do seq, então houve perda de pacote
            cwind, ss_thresh = MD(cwind, ss_thresh)
            curr_file_position_confirmed = ack_to_file_position_and_time[last_ack][0]
            curr_file_position = curr_file_position_confirmed
            pkt.seq = last_ack
            # print("perda de pacote")
        else:  # Se não houve perda de pacote
            if isAtSlowStart(cwind, ss_thresh):
                cwind, ss_thresh = SS(cwind, ss_thresh)
            else:
                cwind, ss_thresh = AI(cwind, ss_thresh)
            curr_file_position_confirmed = curr_file_position
            pkt.seq = last_ack
            # print("sem perda de pacote")

        if last_ack in received_acks:
            RTT = received_acks[last_ack] - ack_to_file_position_and_time[last_ack][1]

        print("last_ack: ", last_ack, " cwind: ", cwind, " ss_thresh: ", ss_thresh, " RTT: ", RTT)
        results.append((cwind, ss_thresh))
        # printa o curr_file_position_confirmed e o curr_file_position e o file_size
        # print("curr_file_position_confirmed, curr_file_position, file_size")
        # print(curr_file_position_confirmed, curr_file_position, file_size)
        # print("cwind, ss_thresh")
        # print(cwind, ss_thresh)

    return pkt.seq, pkt.ack


def mac(interface: str):
    return get_if_hwaddr(interface)


def we_just_sent_it(pkt: Packet):
    if pkt[Ether].src == mac(pkt.sniffed_on):
        return True
    return False


def handle_response(pkt):
    # print("Recebeu pacote")
    # pkt.show()
    received_acks[pkt[TCP].ack] = time.time()


def handle_tcp_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        if pkt[TCP].sport == dst_port and not we_just_sent_it(pkt):
            handle_response(pkt)


def begin_sniff_for_tcp():
    sniffer = AsyncSniffer(iface="h1-eth0", filter="tcp", prn=handle_tcp_packet, quiet=True)
    sniffer.start()


def main():
    # Enviar o pacote de conexão
    seq, ack = begin_connection()
    # Le o arquivo e envia os pacotes
    f = open("lotr.txt", "rb")
    # Cria o pacote com os dados base
    pkt = ip_pkt / TCP(dport=dst_port, flags='PA', seq=seq, ack=ack)
    # Inicia o sniffer
    begin_sniff_for_tcp()
    # Envia os dados
    seq, ack = send_data(f, os.path.getsize("lotr.txt"), pkt, timeout)
    # Enviar o pacote de finalização
    end_connection(seq, ack)

    fig, axs = plt.subplots(1, 1)
    axs.plot([i for i in range(len(results))], [i[0] for i in results], label="cwnd")
    axs.plot([i for i in range(len(results))], [i[1] for i in results], label="ssthresh")
    axs.legend()
    plt.savefig('results.png')
    plt.show()


if __name__ == '__main__':
    main()
