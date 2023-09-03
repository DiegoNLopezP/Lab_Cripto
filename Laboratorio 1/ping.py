import struct
import random
import socket
import time
from scapy.all import IP, ICMP, send

def generate_icmp_packet(data, sequence_number, ipv4_identification):
    # Obtener el timestamp en segundos en orden little-endian
    timestamp = struct.pack("<Q", int(time.time()))

    # Seleccionar un caracter aleatorio del string
    random_char = random.choice(data.encode())

    # Generar el campo de datos como se describe
    data_field = timestamp + bytes([random_char]) + bytes([random.randint(0, 255)]) + bytes.fromhex(
        "080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )

    # Construir el paquete ICMP
    packet = IP(dst="8.8.8.8", id=ipv4_identification) / ICMP(type=8, code=0, id=5, seq=sequence_number) / data_field

    return packet

def send_icmp_packets(data):
    start_ipv4_identification = 5236
    end_ipv4_identification = 57442
    ipv4_identification = start_ipv4_identification

    for i, char in enumerate(data):
        icmp_packet = generate_icmp_packet(char, i + 1, ipv4_identification)
        send(icmp_packet, verbose=False)

        # Incrementar el valor de identification para el siguiente paquete
        ipv4_identification += random.randint(36, 83)
        if ipv4_identification > end_ipv4_identification:
            ipv4_identification = start_ipv4_identification

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Uso: python script.py 'cadena'")
        sys.exit(1)

    input_data = sys.argv[1]
    send_icmp_packets(input_data)

