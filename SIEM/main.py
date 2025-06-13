from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime

# Lista para almacenar eventos
eventos = []

# Función para procesar cada paquete


def procesar_paquete(pkt):
    if IP in pkt:
        evento = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml <- para ver el cod del protocolo
            "protocol": pkt[IP].proto,
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


# Captura en vivo durante 30 segundos o 100 paquetes
print("⏳ Capturando tráfico... (espera unos segundos)")
sniff(prn=procesar_paquete, timeout=30, count=100)

# Guardar como JSON
with open("eventos_red.json", "w") as f:
    json.dump(eventos, f, indent=4)

print(
    f"✅ Captura completa. Se guardaron {len(eventos)} eventos en 'eventos_red.json'")
