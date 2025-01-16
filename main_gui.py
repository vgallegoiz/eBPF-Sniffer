import tkinter as tk
from tkinter import ttk
import threading
import time
from bcc import BPF
import ctypes
import socket
import struct
import psutil
import datetime
from pathlib import Path
import csv
import pymysql
import sys

# --- SQL ---
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='1234Pasd@2023',
    database='ebpf'
)

# --- FUNCIONES AUXILIARES ---

def ns_to_datetime(ns, boot_time_ns):
    """Convierte nanosegundos a una marca de tiempo legible."""
    adjusted_ns = boot_time_ns + ns
    return datetime.datetime.fromtimestamp(adjusted_ns / 1e9).strftime("%Y-%m-%d %H:%M:%S.%f")

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("=I", ip))

def get_protocol(src_port, dst_port):
    protocol = "Unknown"
    if src_port == 53 or dst_port == 53:
        protocol = "DNS"
    elif src_port == 80 or dst_port == 80:
        protocol = "HTTP"
    elif src_port == 443 or dst_port == 443:
        protocol = "HTTPS"
    elif src_port == 22 or dst_port == 22:
        protocol = "SSH"
    elif src_port in [20, 21] or dst_port in [20, 21]:
        protocol = "FTP"
    elif src_port == 23 or dst_port == 23:
        protocol = "Telnet"
    elif src_port == 25 or dst_port == 25:
        protocol = "SMTP"
    elif src_port == 5353 or dst_port == 5353:
        protocol = "mDNS"
    elif src_port in [137, 138] or dst_port in [137, 138]:
        protocol = "NetBIOS"
    return protocol

def get_active_interface():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface != 'lo':
            return interface
    return None

# --- FUNCIONES PARA PROCESAR Y GUARDAR LOS DATOS ---

def update_flows_and_write_csv(bpf, boot_time_ns, csv_writer, table_widget):
    """Actualiza los flujos y los escribe en un archivo CSV."""
    while not stop_program:
        flows_table = bpf.get_table("flows")
        for key in flows_table.keys():
            value = flows_table[key]
            src_ip = ip_to_str(key.src_ip)
            dst_ip = ip_to_str(key.dst_ip)
            src_port = socket.ntohs(key.src_port)
            dst_port = socket.ntohs(key.dst_port)
            protocol = get_protocol(src_port, dst_port)
            score_0 = socket.ntohs(key.score0)
            score_1 = socket.ntohs(key.score1)

            # mirar
            malicious = 0 if score_0 > 500000000000 else 1

            timestamp = ns_to_datetime(value.ts_last, boot_time_ns)
            pkt_length = value.byte_count
            print("ADEUUU")

            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO ebpf (Protocol, Timestamp, Source_IP, Source_Port, Destination_IP, Destination_Port, Packet_Length, Score_1, Score_2, Malicious) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    protocol,  # Protocol
                    timestamp,  # Timestamp
                    src_ip,  # Source IP
                    src_port,  # Source Port
                    dst_ip,  # Destination IP
                    dst_port,  # Destination Port
                    pkt_length,  # Packet Length
                    score_0,  # Score 1
                    score_1,  # Score 2
                    malicious
                )
            )
            #connection.commit()


            # Escribir datos en el archivo CSV
            #csv_writer.writerow([
            #    protocol, timestamp, src_ip, src_port, dst_ip, dst_port,
            #    pkt_length, score_1, score_2
            #])

            # Actualizar la tabla de la interfaz gráfica
            table_widget.insert("", "end", values=(
                protocol, timestamp, src_ip, src_port, dst_ip, dst_port,
                pkt_length, score_0, score_1
            ))
        time.sleep(1)

def calculate_scores(src_port, dst_port, pkt_length):
    """Cálculo de los puntajes Score_1 y Score_2 (puedes personalizar esta función)."""
    score_1 = pkt_length % 100  # Ejemplo: usar el tamaño del paquete como base
    score_2 = (src_port + dst_port) % 50  # Ejemplo: combinar los puertos
    return score_1, score_2

# --- INTERFAZ GRÁFICA CON TKINTER ---

def tkinter_app(interface, bpf, boot_time_ns, csv_writer):
    def add_port():
        try:
            port = int(port_entry.get())
            key = ctypes.c_uint(len(user_data_map))
            value = ctypes.c_ulong(port)
            user_data_map[key] = value
            status_label.config(text=f"Puerto {port} agregado")
        except ValueError:
            status_label.config(text="Entrada de puerto inválida")

    def add_ip():
        try:
            ip = ip_entry.get()
            packed_ip = ctypes.c_uint(int.from_bytes(socket.inet_aton(ip), "little"))
            key = ctypes.c_uint(len(user_ip_map))
            user_ip_map[key] = packed_ip
            status_label.config(text=f"IP {ip} agregada")
        except Exception as e:
            status_label.config(text=f"Error al agregar IP: {e}")

    root = tk.Tk()
    root.title("Monitor de Red con eBPF")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    tk.Label(frame, text="Puerto:").grid(row=0, column=0, padx=5)
    port_entry = tk.Entry(frame)
    port_entry.grid(row=0, column=1, padx=5)
    tk.Button(frame, text="Agregar Puerto", command=add_port).grid(row=0, column=2, padx=5)

    tk.Label(frame, text="IP:").grid(row=1, column=0, padx=5)
    ip_entry = tk.Entry(frame)
    ip_entry.grid(row=1, column=1, padx=5)
    tk.Button(frame, text="Agregar IP", command=add_ip).grid(row=1, column=2, padx=5)

    status_label = tk.Label(root, text="Estado: Esperando acción", fg="blue")
    status_label.pack(pady=5)

    columns = ("Protocol", "Timestamp", "Source IP", "Source Port", "Destination IP",
               "Destination Port", "Packet Length", "Score 1", "Score 2")
    table = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        table.heading(col, text=col)
        table.column(col, anchor="center", width=100)
    table.pack(fill="both", expand=True, padx=10, pady=10)

    # Iniciar el hilo para actualizar flujos y escribir en CSV
    thread = threading.Thread(target=update_flows_and_write_csv, args=(bpf, boot_time_ns, csv_writer, table), daemon=True)
    thread.start()

    root.mainloop()









            
















# --- PROGRAMA PRINCIPAL ---






# Obtener tiempo de inicio del sistema en nanosegundos
boot_time_ns = int((time.time() - psutil.boot_time()) * 1e9)

# Función para obtener la interfaz de red activa (excluyendo "lo")
def get_active_interface():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface != 'lo':
            return interface
    return None

# Obtener la interfaz de red activa
interface = get_active_interface()
if interface is None:
    print("No se encontró una interfaz de red activa.")
    exit()

# Cargar el código eBPF desde un archivo de texto
try:
    bpf_source = Path('ebpf_.c').read_text()
except FileNotFoundError:
    print("No se encontró el archivo 'ebpf_.c'. Por favor, verifica la ubicación del archivo.")
    exit()

# Crear el objeto BPF con el código cargado
bpf = BPF(text=bpf_source)

# Cargar la función eBPF "capture_http_https"
try:
    fn = bpf.load_func("capture_http_https", BPF.XDP)
    bpf.attach_xdp(dev=interface, fn=fn)
    print(f"eBPF cargado y adjuntado a la interfaz {interface}.")
except Exception as e:
    print(f"Error al cargar o adjuntar eBPF: {e}")
    exit()

# Inicializar los mapas definidos en eBPF
user_data_map = bpf["user_data_map"]
user_ip_map = bpf["user_ip_map"]
user_options = bpf["user_options"]

# Configurar valores iniciales para los mapas
# Mapa de datos del usuario (puertos permitidos)
for i in range(4):
    key = ctypes.c_uint(i)  # Clave de 32 bits (u32)
    value = ctypes.c_ulong(0)  # Valor de 64 bits (u64)
    user_data_map[key] = value

# Mapa de IPs permitidas
def ip_to_be32(ip):
    """Convierte una dirección IP a big-endian."""
    return ctypes.c_uint(int.from_bytes(socket.inet_aton(ip), "little"))

for i in range(4):
    key = ctypes.c_uint(i)  # Clave de 32 bits (u32)
    value = ip_to_be32("0.0.0.0")  # IP predeterminada
    user_ip_map[key] = value

# Opciones del usuario (por ejemplo, modo admin o estándar)
key = ctypes.c_uint(0)  # Clave de 32 bits (u32)
if len(sys.argv) > 1 and sys.argv[1] == "admin":
    value = ctypes.c_ulong(1)  # Activar modo admin
    user_options[key] = value
    print("Modo admin activado.")
else:
    value = ctypes.c_ulong(0)  # Modo estándar
    user_options[key] = value
    print("Modo estándar activado.")

# Variable para controlar la ejecución del programa
stop_program = False

try:
    # Crear un archivo CSV para almacenar los datos
    with open('captured_packets.csv', mode='w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        
        # Escribir el encabezado del archivo CSV
        csv_writer.writerow([
            "Protocol", "Timestamp", "Source_IP", "Source_Port", "Destination_IP", 
            "Destination_Port", "Packet_Length", "Score_1", "Score_2"
        ])

        # Iniciar la interfaz gráfica con el monitor eBPF
        tkinter_app(interface, bpf, boot_time_ns, csv_writer)
except KeyboardInterrupt:
    # Detener el programa de forma segura en caso de interrupción
    stop_program = True
    print("Interrumpido por el usuario.")
finally:
    # Desactivar eBPF al salir
    try:
        bpf.remove_xdp(dev=interface)
        print("eBPF desactivado de la interfaz.")
    except Exception as e:
        print(f"Error al desactivar eBPF: {e}")
