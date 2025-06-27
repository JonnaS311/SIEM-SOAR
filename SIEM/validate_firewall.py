import asyncio
import json
import time
from pysnmp.hlapi.asyncio import (
    get_cmd as nextCommand,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity
)

# Configuración SNMP
COMMUNITY_STRING = 'public'
AGENT_HOST = '192.168.1.1'
OID_TO_WALK = '.1.3.6.1.4.1.8072.1.3.2.3.1.1.15.102.105.114.101.119.97.108.108.45.115.116.97.116.117.115'
ARCHIVO_EVENTOS = 'eventos_firewall.jsonl'

async def perform_snmp_walk(host, community, oid):
    """
    Realiza un SNMP walk asíncrono y devuelve los resultados.
    """
    print(f"[{time.strftime('%H:%M:%S')}] Realizando SNMP walk en {host}")
    try:
        transport_target = await UdpTransportTarget.create(
            (host, 161), timeout=2, retries=2
        )

        # Usamos nextCommand para un walk
        errorIndication, errorStatus, errorIndex, varBinds = await nextCommand(
            SnmpEngine(),
            CommunityData(community, mpModel=1), # mpModel=1 para SNMPv2c
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False # Para asegurar que haga un walk completo
        )

        if errorIndication:
            print(f"Error en SNMP walk: {errorIndication}")
        elif errorStatus:
            print(f"Error de estado SNMP: {errorStatus.prettyPrint()} en {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
        else:
            found_firewall_status = False
            for varBind in varBinds:
                if int(varBind[1]) == 1:
                    found_firewall_status = True
                    print(f"🟢 El estado del firewall para el dispositivo {AGENT_HOST} es: Enable")
                    break
            if not found_firewall_status:
                print("🔴 Estado Disable o no encontrado 'firewall-status'.")
                # enviar alerta aquí
                evento = dict()
                evento["firewall"] = 0
                evento["host"] = AGENT_HOST
                try:
                    with open(ARCHIVO_EVENTOS, "a") as f:
                        # json.dumps convierte el diccionario de Python a un string JSON
                        f.write(json.dumps(evento) + "\n")
                except IOError as e:
                    print(f"❌ Error al escribir en el archivo: {e}")

    except Exception as e:
        print(f"Excepción inesperada durante SNMP walk: {e}")

async def main():
    """
    Función principal que ejecuta el SNMP walk cada 30 segundos.
    """
    while True:
        await perform_snmp_walk(AGENT_HOST, COMMUNITY_STRING, OID_TO_WALK)
        print("-" * 30) # Separador para facilitar la lectura entre checks
        await asyncio.sleep(8) # Espera 30 segundos antes de la próxima verificación

if __name__ == "__main__":
    asyncio.run(main())