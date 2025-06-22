import asyncio
import json
import time
import subprocess
from collections import defaultdict, deque
from pysnmp.hlapi import *
from SIEM.validate_IP import check_ip_reputation

# --- Configuracion ---
EVENTOS_REDES_FILE = "eventos_red.jsonl"
EVENTOS_DDOS_FILE = "eventos_DDOS.jsonl"
MALICIOUS_IP_THRESHOLD = 5
WINDOW_SECONDS = 60

evento_ip_timeline = defaultdict(lambda: deque())

# --- Acciones SOAR ---
async def block_ip(ip_address):
    print(f"⛘️ [SOAR] Intentando bloquear IP maliciosa: {ip_address}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"✅ [SOAR] IP {ip_address} bloqueada exitosamente.")
    except subprocess.CalledProcessError as e:
        print(f"❌ [SOAR] Error al ejecutar iptables: {e}")
    await asyncio.sleep(0.5)

async def isolate_interface(interface_name):
    print(f"🚧 [SOAR] Aislando interfaz: {interface_name}")
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface_name, "down"], check=True)
        print(f"✅ [SOAR] Interfaz {interface_name} desactivada temporalmente.")
        await asyncio.sleep(5)  # Tiempo simulado de mitigación
        subprocess.run(["sudo", "ip", "link", "set", interface_name, "up"], check=True)
        print(f"✅ [SOAR] Interfaz {interface_name} reactivada.")
    except subprocess.CalledProcessError as e:
        print(f"❌ [SOAR] Error al aislar la interfaz: {e}")
    await asyncio.sleep(0.5)

async def create_ticket(title, description):
    print(f"🎫 [SOAR] Ticket creado: {title}\n    {description}")
    await asyncio.sleep(0.5)

async def send_notification(message):
    print(f"📧 [SOAR] Notificación enviada: {message}")
    await asyncio.sleep(0.5)

# --- Ingesta de eventos ---
async def tail_file(path, queue):
    with open(path, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(1)
                continue
            try:
                evento = json.loads(line)
                await queue.put(evento)
            except json.JSONDecodeError:
                continue

# --- Correlacionadores ---
async def handle_red_event(evento):
    ip = evento.get('src_ip')
    mal = evento.get('malicius_IP', False)
    ts = time.time()

    if mal:
        dq = evento_ip_timeline[ip]
        dq.append(ts)
        while dq and dq[0] < ts - WINDOW_SECONDS:
            dq.popleft()

        if len(dq) >= MALICIOUS_IP_THRESHOLD:
            print(f"🔴 [SOAR] Umbral superado para {ip}: {len(dq)} alertas en {WINDOW_SECONDS}s")
            await block_ip(ip)
            await create_ticket(f"Bloqueo automático de IP {ip}", f"{len(dq)} eventos maliciosos de {ip} en {WINDOW_SECONDS} segundos.")
            await send_notification(f"IP {ip} bloqueada automáticamente.")
            dq.clear()

async def handle_ddos_event(evento):
    volumen_str = evento.get('Volumen', '')
    interfaz = evento.get('Interfaz', '<desconocida>')

    try:
        parte = volumen_str.split(' MB')[0]
        mb = float(parte)
    except Exception:
        mb = 0.0

    if mb > 5.0:
        print(f"🔴 [SOAR] Detección DDOS: {volumen_str} en {interfaz}")
        await isolate_interface(interfaz)
        await create_ticket("Alerta DDOS automática", f"Se detectó DDOS en interfaz {interfaz}: {volumen_str}.")
        await send_notification(f"Interfaz {interfaz} fue temporalmente desactivada por DDOS.")

# --- Loop principal ---
async def main():
    queue_red = asyncio.Queue()
    queue_ddos = asyncio.Queue()
    asyncio.create_task(tail_file(EVENTOS_REDES_FILE, queue_red))
    asyncio.create_task(tail_file(EVENTOS_DDOS_FILE, queue_ddos))
    print("🚀 [SOAR] Orquestador iniciado. Esperando eventos...")

    while True:
        done, _ = await asyncio.wait([
            queue_red.get(),
            queue_ddos.get()
        ], return_when=asyncio.FIRST_COMPLETED)

        for task in done:
            evento = task.result()
            if 'src_ip' in evento:
                asyncio.create_task(handle_red_event(evento))
            else:
                asyncio.create_task(handle_ddos_event(evento))

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("⛔️ [SOAR] Orquestador detenido por el usuario.")
