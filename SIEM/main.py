from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime
import ipaddress
import pandas as pd
import re
import bisect

# Lista para almacenar eventos
eventos = []

# Cargar dataset limpio con rangos IP
file_path = "./SIEM/regiones_IP/IP2LOCATION-LITE-DB1.CSV"
df = pd.read_csv(file_path, header=None, names=[
                 "ip_from", "ip_to", "country_code", "country_name"])

# Convertir IPs a enteros para comparar más fácilmente
ip_starts = df["ip_from"].tolist()
ip_ends = df["ip_to"].tolist()
countries = df["country_name"].tolist()

# Regex para detectar IPs privadas
regex = r"\b(?:10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3}))\b"

# Función para procesar cada paquete


def procesar_paquete(pkt):

    # Función de búsqueda
    def buscar_pais_por_ip(ip_str):
        ip_int = int(ipaddress.IPv4Address(ip_str))
        idx = bisect.bisect_right(ip_starts, ip_int) - 1
        if idx >= 0 and ip_ends[idx] >= ip_int:
            return countries[idx]
        return "Desconocido"

    if IP in pkt and not bool(re.search(regex, pkt[IP].src)):
        evento = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml <- para ver el cod del protocolo
            "protocol": pkt[IP].proto,
            "pais": buscar_pais_por_ip(pkt[IP].src)
        }

        # Añadir puertos si es TCP o UDP
        if TCP in pkt:
            evento["src_port"] = pkt[TCP].sport
            evento["dst_port"] = pkt[TCP].dport
            evento["layer"] = "TCP"
        elif UDP in pkt:
            evento["src_port"] = pkt[UDP].sport
            evento["dst_port"] = pkt[UDP].dport
            evento["layer"] = "UDP"
        else:
            evento["layer"] = "Otro"

        eventos.append(evento)
        print(evento)


# Captura en vivo durante 30 segundos o 100 paquetes
print("⏳ Capturando tráfico... (espera unos segundos)")
sniff(prn=procesar_paquete, timeout=30, count=100)

# Guardar como JSON
with open("eventos_red.json", "w") as f:
    json.dump(eventos, f, indent=4)

print(
    f"✅ Captura completa. Se guardaron {len(eventos)} eventos en 'eventos_red.json'")
