import os 
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.all import sr1, send, sniff, Raw, sr

ip_src = '10.1.1.1'
ip_dst = '10.1.1.2'
dst_port = 8881
timeout = 1
# Maximum Segment Size
MSS = 500

ip_pkt = IP(src=ip_src, dst=ip_dst)

seqs_sent = []

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

# Função para enviar o pacote de dados
def send_pkt(pkt, file, curr_file_position):
    file.seek(curr_file_position)
    data = file.read(MSS)
    send(pkt / data, verbose=False)

# Função para enviar o pacote de dados e receber a confirmação
def sr1_pkt(pkt, file, curr_file_position, timeout):
    file.seek(curr_file_position)
    data = file.read(MSS)

    while True:
        respondidos, nao_respondidos = sr(pkt / data, timeout=timeout, verbose=False)
        if len(respondidos) != 0:
            print("Tamanho da lista de respondidos:", respondidos)
            print(nao_respondidos)
            return respondidos[0][1].ack

def CriaPacote(seq, ack):
    return ip_pkt / TCP(dport=dst_port, flags='PA', seq=seq, ack=ack)

def send_data(file, file_size, pkt, timeout):
    pkts_to_send = 3
    curr_file_position = 0
    curr_file_position_confirmed = 0

    # Enquanto a posição atual do arquivo for menor que o tamanho do arquivo
    while curr_file_position_confirmed < file_size:
        listaDePacotes = []
        # For para enviar os pacotes considerando o numero de pacotes que podem ser enviados
        for _ in range(pkts_to_send - 1):
            # Adiciona a sequencia do pacote na lista de sequencias enviadas
            seqs_sent.append(pkt.seq)
            # Envia o pacote
            send_pkt(pkt, file, curr_file_position)
            # Atualiza o numero de sequencia do pacote
            if(curr_file_position + MSS > file_size):
                pkt.seq = pkt.seq + (file_size - curr_file_position)
            else:
                pkt.seq = pkt.seq + MSS
            # Atualiza a posição atual do arquivo não confirmada
            curr_file_position = curr_file_position + MSS
        
        ack = sr1_pkt(pkt, file, curr_file_position, timeout)

        if ack != pkt.seq + MSS:
            print("Erro no envio do pacote, sequencia:", pkt.seq + MSS, "ack:", ack)
            curr_file_position = curr_file_position_confirmed
        else:
            curr_file_position = curr_file_position + MSS
            curr_file_position_confirmed = curr_file_position - MSS
        pkt.seq = ack
        
    return pkt.seq, pkt.ack
    
def main():
    # Enviar o pacote de conexão
    seq, ack = begin_connection()
    # Le o arquivo e envia os pacotes
    f = open("lotr copy.txt", "rb")
    # Cria o pacote com os dados base
    pkt = ip_pkt / TCP(dport=dst_port, flags='PA', seq=seq, ack=ack)
    # Envia os dados
    seq, ack = send_data(f, os.path.getsize("lotr.txt"), pkt, timeout)
    # Enviar o pacote de finalização
    end_connection(seq, ack)

if __name__ == '__main__':
    main()
