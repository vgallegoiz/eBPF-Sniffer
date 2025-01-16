from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv
import os
from decision_tree_model import score  # Importamos la función score

def process_packet(packet):
    """
    Procesa un paquete capturado y devuelve una tupla con los detalles.
    """
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        packet_info = None

        # Aquí se extraen las características relevantes para el árbol de decisión.
        packet_features = []

        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info = (
                "TCP",
                timestamp,
                src_ip,
                tcp_layer.sport,
                dst_ip,
                tcp_layer.dport,
                len(packet)
            )
            # Usamos el tamaño del paquete, el puerto de origen y el puerto de destino como entrada
            packet_features = [len(packet), tcp_layer.sport, tcp_layer.dport]
        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_info = (
                "UDP",
                timestamp,
                src_ip,
                udp_layer.sport,
                dst_ip,
                udp_layer.dport,
                len(packet)
            )
            # Usamos el tamaño del paquete, el puerto de origen y el puerto de destino como entrada
            packet_features = [len(packet), udp_layer.sport, udp_layer.dport]
        else:
            packet_info = (
                "Other",
                timestamp,
                src_ip,
                None,
                dst_ip,
                None,
                len(packet)
            )
            # Características generales si no es TCP o UDP
            packet_features = [len(packet)]  # Agregamos solo el tamaño

        # Llamamos a la función score para obtener el resultado del árbol de decisión
        score_result = score(packet_features)
        print(f"Score result for packet {packet_info}: {score_result}")

        # Añadimos los resultados de score a la información del paquete
        packet_info += (score_result[0], score_result[1])

        return packet_info
    return None

def start_sniffer(interface, csv_writer):
    """
    Inicia la captura de paquetes y escribe los resultados en un archivo CSV.
    """
    print(f"Starting sniffer on interface {interface}...")

    def packet_handler(packet):
        result = process_packet(packet)
        if result:
            csv_writer.writerow(result)

    sniff(iface=interface, filter="ip", prn=packet_handler, store=False)

if __name__ == "__main__":
    # Determinar la interfaz de red a usar
    print("Available network interfaces:")
    os.system("ip link show")  # Muestra las interfaces disponibles en sistemas basados en Linux
    interface = input("\nEnter the interface to sniff on: ")

    try:
        # Crear un archivo CSV y escribir el encabezado
        with open('captured_packets.csv', mode='+w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            # Ajustar el encabezado sin Protocol_Number
            csv_writer.writerow(["Protocol", "Timestamp", "Source_IP", "Source_Port", "Destination_IP", "Destination_Port", "Packet_Length", "Score_1", "Score_2"])

            # Iniciar el sniffer
            start_sniffer(interface, csv_writer)
            print("\nSniffer detenido por el usuario.")
    except PermissionError:
        print("Error: Debes ejecutar este programa con permisos de administrador.")
    except KeyboardInterrupt:
        print("\nSniffer detenido por el usuario.")
    except Exception as e:
        print(f"Error: {e}")
