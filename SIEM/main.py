from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime
from validate_IP import check_ip_reputation  # Asegúrate de que este módulo exista y funcione
import ipaddress
import pandas as pd
import re
import bisect
import sys
import time

# --- CONFIGURACIÓN INICIAL ---

# Lista de países considerados de alto riesgo
paises_riesgosos = {
    "RU",  # Russia
    "CN",  # China
    "IR",  # Iran
    "KP",  # North Korea
    "VN",  # Vietnam
    "PK",  # Pakistan
    "SY",  # Syria
    "BY",  # Belarus
    "UZ",
    "UA"   # Ukraine
}

# Regex para detectar y excluir IPs privadas
REGEX_IP_PRIVADA = r"\b(?:10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3}))\b"

# Nombre del archivo de salida. Usamos .jsonl (JSON Lines) que es ideal para logs.
ARCHIVO_EVENTOS = "eventos_red.jsonl"

# --- CARGA DEL DATASET DE IPs ---
try:
    print("Cargando base de datos de geolocalización de IP...")
    file_path = "./SIEM/regiones_IP/IP2LOCATION-LITE-DB1.CSV"
    df = pd.read_csv(file_path, header=None, names=[
                     "ip_from", "ip_to", "country_code", "country_name"])

    # Convertir IPs a enteros para búsquedas eficientes
    ip_starts = df["ip_from"].tolist()
    ip_ends = df["ip_to"].tolist()
    countries = df["country_code"].tolist()
    print("✅ Base de datos cargada correctamente.")
except FileNotFoundError:
    print(f"❌ Error: No se encontró el archivo en la ruta '{file_path}'. Asegúrate de que el archivo exista.")
    sys.exit(1) # Termina el script si no se encuentra el archivo de IPs

# --- FUNCIONES DE PROCESAMIENTO ---

def buscar_pais_por_ip(ip_str):
    """
    Busca el código de país para una IP dada usando búsqueda binaria en el DataFrame cargado.
    """
    try:
        ip_int = int(ipaddress.IPv4Address(ip_str))
        # bisect_right es muy eficiente para encontrar el índice correcto en una lista ordenada
        idx = bisect.bisect_right(ip_starts, ip_int) - 1
        if idx >= 0 and ip_ends[idx] >= ip_int:
            return countries[idx]
    except ValueError:
        return "IP Inválida"
    return "Desconocido"

def procesar_paquete(pkt):
    """
    Función que se llama por cada paquete capturado por Scapy.
    Analiza, enriquece y guarda los eventos de interés.
    """
    # Ignorar paquetes que no tengan capa IP o que provengan de una IP privada
    if not IP in pkt or bool(re.search(REGEX_IP_PRIVADA, pkt[IP].src)):
        return

    evento = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": pkt[IP].proto, # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        "pais": buscar_pais_por_ip(pkt[IP].src)
    }

    evento["alerta"] = "Trafico desde pais de alto riesgo" if evento["pais"] in paises_riesgosos else "OK"

    # Añadir detalles de capa de transporte (TCP/UDP)
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

    # Si el evento es una alerta, se enriquece y se guarda
    if evento["alerta"] != "OK":
        # Esta función puede hacer una petición a una API, lo cual puede ser lento.
        # Considera ejecutarla en un hilo separado si el rendimiento es crítico.
        reputacion = check_ip_reputation(pkt[IP].src)
        if reputacion:
            evento["malicius_IP"] = reputacion

        # Guardar el evento como una nueva línea en el archivo JSONL
        try:
            with open(ARCHIVO_EVENTOS, "a") as f:
                # json.dumps convierte el diccionario de Python a un string JSON
                f.write(json.dumps(evento) + "\n")
        except IOError as e:
            print(f"❌ Error al escribir en el archivo: {e}")

        # Imprimir en consola para feedback en tiempo real
        print(f"🚨 Alerta detectada y guardada: {evento}")


# --- EJECUCIÓN PRINCIPAL ---

if __name__ == "__main__":
    print("\n⏳ Iniciando captura de tráfico en modo continuo...")
    print(f"📝 Los eventos de alerta se guardarán en '{ARCHIVO_EVENTOS}'")
    print("ℹ️  Presiona CTRL+C para detener la captura.")
    
    try:
        # Iniciar la captura sin límites de tiempo o paquetes
        sniff(prn=procesar_paquete, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Captura detenida por el usuario.")
    except Exception as e:
        print(f"\n❌ Ha ocurrido un error inesperado: {e}")
    finally:
        print("✅ Script finalizado.")