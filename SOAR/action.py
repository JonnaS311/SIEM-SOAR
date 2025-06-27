import asyncio
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
    except Exception as e:
        print(f"Excepción inesperada durante SNMP walk: {e}")