import asyncio
import json
import time
from pysnmp.hlapi.asyncio import (
    get_cmd as getCmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity
)


# --- CONFIGURACIÓN ---
# ---------------------------------------------------------------------
TARGET = '192.168.1.1'
COMMUNITY = 'public'
INTERFACE_INDEX = 3
INTERVAL = 5
THRESHOLD = 2_857_600 # Umbral de ~100 Megabytes
OID = f'1.3.6.1.2.1.2.2.1.10.{INTERFACE_INDEX}' # ifInOctets para la interfaz 3
ARCHIVO_EVENTOS = 'eventos_DDOS.jsonl'

# --- Función para obtener datos SNMP de forma asíncrona ---
async def snmp_get(snmp_engine, oid):
    """
    Realiza una petición SNMP GET de forma asíncrona.
    SOLUCIÓN AL ERROR: Se usa 'await UdpTransportTarget.create()' que es la
    forma correcta de instanciar el transporte en el modo asyncio.
    """
    try:
        # ---- INICIO DE LA CORRECCIÓN FINAL ----
        # Se crea el objeto de transporte de forma asíncrona usando .create()
        # y se pasan el timeout/retries directamente como argumentos.
        transport_target = await UdpTransportTarget.create(
            (TARGET, 161), timeout=2, retries=2
        )

        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            snmp_engine,
            CommunityData(COMMUNITY, mpModel=0),
            transport_target, # <-- Se pasa el objeto ya creado de forma asíncrona
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        if errorIndication:
            print(f"Error de SNMP: {errorIndication}")
        elif errorStatus:
            error_msg = errorStatus.prettyPrint()
            error_details = varBinds[int(errorIndex) - 1] if errorIndex else '?'
            print(f"Error en respuesta SNMP: {error_msg} en {error_details}")
            return None
        else:
            return varBinds
    except Exception as e:
        print(f"Error inesperado durante la operación SNMP: {e}")
        return None
    
async def get_interface_name_by_index(hostname, community, interface_index):
    """
    Obtiene el nombre de una interfaz SNMP dado su índice.

    Args:
        hostname (str): La dirección IP o nombre de host del dispositivo SNMP.
        community (str): La cadena de comunidad SNMP (ej. 'public').
        interface_index (int): El índice de la interfaz que deseas consultar.

    Returns:
        str: El nombre de la interfaz o None si no se encuentra.
    """
    # El OID para ifDescr es 1.3.6.1.2.1.2.2.1.2
    # Para consultar un elemento específico por su índice, concatenamos el OID con el índice.
    # Por ejemplo, para ifDescr del índice 1, el OID completo sería 1.3.6.1.2.1.2.2.1.2.1
    oid = f'1.3.6.1.2.1.2.2.1.2.{interface_index}'
    transport_target = await UdpTransportTarget.create(
        (TARGET, 161), timeout=2, retries=2
    )


    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(SnmpEngine(),
               CommunityData(community, mpModel=0),
               transport_target,
               ContextData(),
               ObjectType(ObjectIdentity(oid)))

    if errorIndication:
        print(f"Error en la consulta SNMP: {errorIndication}")
    elif errorStatus:
        print(f"Error en la respuesta SNMP: {errorStatus.prettyPrint()} en {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
        return None
    else:
        for varBind in varBinds:
            # varBind será algo como (ObjectIdentity('1.3.6.1.2.1.2.2.1.2.1'), DisplayString('lo'))
            # El segundo elemento de la tupla es el valor, que es el nombre de la interfaz.
            return str(varBind[1]) # Convertimos el valor a string

# --- Función principal para el monitoreo ---
async def monitor_ddos():
    snmp_engine = SnmpEngine()
    varBinds = await snmp_get(snmp_engine, OID) 
    last_count = int(varBinds[0][1])
   

    if last_count is None:
        print("\nError fatal en la lectura inicial de SNMP.")
        print("El script no puede continuar. Revisa los mensajes de error anteriores.")
        return

    print("=" * 50)
    print(f"Iniciando monitoreo en: {TARGET} (Interfaz: {INTERFACE_INDEX})")
    print(f"OID monitoreado: {OID} (ifInOctets)")
    print(f"Intervalo de sondeo: {INTERVAL} segundos")
    print(f"Umbral de alerta: > {THRESHOLD / 1_048_576:.2f} MB / {INTERVAL}s")
    print("=" * 50)

    while True:
        await asyncio.sleep(INTERVAL)
        varBinds = await snmp_get(snmp_engine, OID)
        current_count = int(varBinds[0][1])
        

        if current_count is None:
            print("Fallo en lectura SNMP. Se reintentará en el próximo ciclo.")
            continue

        if current_count < last_count:
            print(f"(Detectado desbordamiento de contador: {last_count} -> {current_count})")
            diff = (2**32 - 1 - last_count) + current_count
        else:
            diff = current_count - last_count
        
        rate_MBps = diff / (INTERVAL * 1_048_576)

        if diff > THRESHOLD:
            print(f"🔴 [ALERTA] Tráfico anómalo detectado.")
            print(f"   Volumen: {diff / 1_048_576:.2f} MB en {INTERVAL}s ({rate_MBps:.2f} MB/s). Umbral: {THRESHOLD / 1_048_576:.2f} MB")
            # Guardar el evento como una nueva línea en el archivo JSONL
            evento = dict()
            
            evento = {
                "Volumen": f"{diff / 1_048_576:.2f} MB en {INTERVAL}s ({rate_MBps:.2f} MB/s)",
                "Umbral": f"{THRESHOLD / 1_048_576:.2f} MB"
            }
            evento['IP']= TARGET
            evento['Interfaz']= await get_interface_name_by_index(TARGET, COMMUNITY, INTERFACE_INDEX)
            try:
                with open(ARCHIVO_EVENTOS, "a") as f:
                    # json.dumps convierte el diccionario de Python a un string JSON
                    f.write(json.dumps(evento) + "\n")
            except IOError as e:
                print(f"❌ Error al escribir en el archivo: {e}")
        else:
            print(f"🟢 Tráfico normal: {diff / 1_048_576:.2f} MB en {INTERVAL}s ({rate_MBps:.2f} MB/s)")

        last_count = current_count

# --- Punto de entrada principal del script ---
if __name__ == "__main__":
    while True:
        try:
            asyncio.run(monitor_ddos())
        except KeyboardInterrupt:
            print("\n\nMonitoreo detenido por el usuario. ¡Adiós!")
        except TypeError:
            print("Intefaz dada de baja...")
            time.sleep(10)
            continue
        except Exception as e:
            print(f"\nSe ha producido un error crítico no manejado: {e}")
