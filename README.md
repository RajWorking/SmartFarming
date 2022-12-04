# LatticeCrypto

instructions
```
# IOT Smart Device 1
python3 SN1.py <bind_ip> <bind_port> <GWN_ip> <GWN_port>

# IOT Smart Device 2
python3 SN2.py <SN1_ip> <SN1_port>

# Gateway Node
python3 GatewayNode.py <bind_ip> <bind_port> <Edgeserver_ip> <Edgeserverr_port>

# Edgeserver
python3 EdgeServer.py <bind_ip> <bind_port> <CloudServer_ip> <CloudServer_port>

# Cloud Server
python3 <bind_ip> <bind_port>
```