import pandas as pd
import socket
import struct


# Link base de datos -> https://download.ip2location.com/lite/
# Cargar el archivo CSV subido
file_path = "./SIEM/regiones_IP/IP2LOCATION-LITE-DB1.CSV"
df = pd.read_csv(file_path, header=None, names=[
                 "ip_from", "ip_to", "country_code", "country_name"])

df = df.iloc[1:]

# Verificar si está ordenado
print(df["ip_from"].is_monotonic_increasing)

# Función para convertir IP decimal a formato IPv4


def decimal_to_ip(ip_decimal):
    return socket.inet_ntoa(struct.pack('!I', int(ip_decimal)))


# Aplicar la conversión a las columnas ip_from e ip_to
df["ip_from_str"] = df["ip_from"].apply(decimal_to_ip)
df["ip_to_str"] = df["ip_to"].apply(decimal_to_ip)

# Reorganizar columnas para legibilidad
df_final = df[["ip_from_str", "ip_to_str", "country_code", "country_name"]]
df_final.columns = ["ip_from", "ip_to", "code", "country"]

# Guardar el resultado como un nuevo CSV
output_path = "./SIEM/regiones_IP/ip_ranges_readable.csv"
df_final.to_csv(output_path, index=False)

output_path
