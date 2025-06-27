import asyncio
import json
import time
import subprocess
from collections import defaultdict, deque
from pysnmp.hlapi.asyncio import (
    get_cmd as nextCommand,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity
)

from action import perform_snmp_walk

# --- Configuracion ---
EVENTOS_REDES_FILE = "eventos_red.jsonl"
EVENTOS_FIREWALL_FILE = "eventos_firewall.jsonl"
EVENTOS_DDOS_FILE = "eventos_DDOS.jsonl"
MALICIOUS_IP_THRESHOLD = 2
WINDOW_SECONDS = 60

# Configuración SNMP
COMMUNITY_STRING = 'public'
AGENT_HOST = '192.168.1.1'
OID_TO_DOWN_INTERFACE = '.1.3.6.1.4.1.8072.1.3.2.3.1.1.15.105.102.97.99.101.45.100.111.119.110.45.119.108.111.49'
OID_TO_ACT_FIREWALL = '.1.3.6.1.4.1.8072.1.3.2.3.1.1.12.102.105.114.101.119.97.108.108.45.97.99.116'


evento_ip_timeline = defaultdict(lambda: deque())

# --- Acciones SOAR ---
async def block_ip(ip_address):
    print(f"⛘️ [SOAR] Intentando bloquear IP maliciosa: {ip_address}")
    try:
        # Usamos asyncio.create_subprocess_exec para no bloquear el bucle de eventos
        proc = await asyncio.create_subprocess_exec(
            "sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            print(f"✅ [SOAR] IP {ip_address} bloqueada exitosamente.")
        else:
            print(f"❌ [SOAR] Error al ejecutar iptables: {stderr.decode().strip()}")
    except Exception as e:
        print(f"❌ [SOAR] Excepción al bloquear IP: {e}")
    await asyncio.sleep(0.5)

async def isolate_interface(interface_name):
    print(f"🚧 [SOAR] Aislando interfaz: {interface_name}")
    try:
        # Desactivar
        #proc_down = await asyncio.create_subprocess_exec("sudo", "ip", "link", "set", interface_name, "down")
        #await proc_down.wait()
        snmp_engine = SnmpEngine()
        varBinds = await perform_snmp_walk(AGENT_HOST, COMMUNITY_STRING, OID_TO_DOWN_INTERFACE) 
        print(varBinds)
    except Exception as e:
        print(f"❌ [SOAR] Excepción al aislar la interfaz: {e}")
    await asyncio.sleep(0.5)

async def activate_firewall():
    print(f"🚧 [SOAR] Encendiendo firewall: {AGENT_HOST}")
    try:
        # Desactivar
        snmp_engine = SnmpEngine()
        varBinds = await perform_snmp_walk(AGENT_HOST, COMMUNITY_STRING, OID_TO_ACT_FIREWALL) 
        print(varBinds)
    except Exception as e:
        print(f"❌ [SOAR] Excepción al encender firewall: {e}")
    await asyncio.sleep(0.5)

async def create_ticket(title, description):
    print(f"🎫 [SOAR] Ticket creado: {title}\n    {description}")
    await asyncio.sleep(0.5)

async def send_notification(message):
    print(f"📧 [SOAR] Notificación enviada: {message}")
    await asyncio.sleep(0.5)

# --- Ingesta de eventos ---
async def tail_file(path, queue):
    try:
        with open(path, 'r') as f:
            f.seek(0, 2) # Ir al final del archivo
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(1)
                    continue
                try:
                    evento = json.loads(line)
                    await queue.put(evento)
                except json.JSONDecodeError:
                    print(f"⚠️ [SOAR] Línea malformada en {path}: {line.strip()}")
                    continue
    except FileNotFoundError:
        print(f"❌ [SOAR] Error: El archivo {path} no fue encontrado. Creándolo.")
        open(path, 'w').close()
        # Reintentar la función después de crear el archivo
        await tail_file(path, queue)


# --- Correlacionadores ---
async def handle_red_event(evento):
    ip = evento.get('src_ip')
    mal = evento.get('malicius_IP', False)
    ts = time.time()
    print(ip)
    if mal and ip:
        dq = evento_ip_timeline[ip]
        dq.append(ts)
        while dq and dq[0] < ts - WINDOW_SECONDS:
            dq.popleft()
        print(dq)
        if len(dq) >= MALICIOUS_IP_THRESHOLD:
            print('here')
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
    except (ValueError, IndexError):
        mb = 0.0

    if mb > 5.0:
        print(f"🔴 [SOAR] Detección DDOS: {volumen_str} en {interfaz}")
        await isolate_interface(interfaz)
        await create_ticket("Alerta DDOS automática", f"Se detectó DDOS en interfaz {interfaz}: {volumen_str}.")
        await send_notification(f"Interfaz {interfaz} fue temporalmente desactivada por DDOS.")


async def handle_firewall_event(evento):
    firewall_status = evento.get('firewall', '')
    origen = evento.get('host', '<desconocida>')

    if firewall_status == 0:
        print(f"🔴 [SOAR] Detección Firewall desactivado en {origen}")
        await activate_firewall()
        await create_ticket("Alerta Firewall desactivado automática", f"Se detectó firwall desactivado en {origen}.")
        await send_notification(f"Host {origen} fue activado.")

# --- Loop principal (CORREGIDO) ---
async def main():
    queue_red = asyncio.Queue()
    queue_ddos = asyncio.Queue()
    queue_firewall = asyncio.Queue()
    
    # Inicia las tareas que leen los archivos en segundo plano
    asyncio.create_task(tail_file(EVENTOS_REDES_FILE, queue_red))
    asyncio.create_task(tail_file(EVENTOS_DDOS_FILE, queue_ddos))
    asyncio.create_task(tail_file(EVENTOS_FIREWALL_FILE, queue_firewall))
    
    print("🚀 [SOAR] Orquestador iniciado. Esperando eventos...")

    while True:
        # 1. Crea las tareas para esperar en cada cola
        task_red_get = asyncio.create_task(queue_red.get())
        task_ddos_get = asyncio.create_task(queue_ddos.get())
        task_firewall_get = asyncio.create_task(queue_firewall.get())

        tasks_to_wait_on = [task_red_get, task_ddos_get, task_firewall_get]

        # 2. Usa asyncio.wait con el conjunto de tareas
        done, pending = await asyncio.wait(tasks_to_wait_on, return_when=asyncio.FIRST_COMPLETED)

        # 3. Cancela la tarea pendiente para que no siga consumiendo recursos
        for task in pending:
            task.cancel()

        # 4. Procesa la(s) tarea(s) que sí se completaron
        for task in done:
            try:
                evento = task.result()
                if 'src_ip' in evento:
                    asyncio.create_task(handle_red_event(evento))
                elif 'Interfaz' in evento:
                    asyncio.create_task(handle_ddos_event(evento))
                else:
                    asyncio.create_task(handle_firewall_event(evento))
            except asyncio.CancelledError:
                # Es normal que una tarea cancelada lance este error al obtener el resultado.
                pass
            except Exception as e:
                print(f"🚨 [SOAR] Error procesando evento: {e}")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⛔️ [SOAR] Orquestador detenido por el usuario.")