from scapy.all import rdpcap, TCP
import pandas as pd

PCAP_FILE = "Modbus_capture.pcap"  # adapte si l'extension est différente
MODBUS_PORT = 502  # port Modbus/TCP standard

def extract_modbus_messages(pcap_file):
    packets = rdpcap(pcap_file)
    messages = []

    for pkt in packets:
        # On garde uniquement les paquets TCP avec du Modbus (port 502 client ou serveur)
        if TCP in pkt and (pkt[TCP].sport == MODBUS_PORT or pkt[TCP].dport == MODBUS_PORT):
            payload_bytes = bytes(pkt[TCP].payload)
            if len(payload_bytes) == 0:
                continue  # pas de données applicatives

            # Clé de flux : (IP_src, port_src, IP_dst, port_dst)
            try:
                ip_layer = pkt["IP"]
                flow_key = (
                    ip_layer.src,
                    pkt[TCP].sport,
                    ip_layer.dst,
                    pkt[TCP].dport,
                )
            except Exception:
                # Ignore paquets bizarres sans IP (par ex. IPv6 si pas géré ici)
                continue

            messages.append({
                "flow": flow_key,
                "length": len(payload_bytes),
                "payload": payload_bytes,
            })

    # DataFrame pratique pour la suite
    df = pd.DataFrame(messages)
    return df


df = extract_modbus_messages(PCAP_FILE)
print("Nombre de messages Modbus trouvés :", len(df))
print(df.head())
# Sauvegarde brute pour debug / étape suivante
df.to_pickle("modbus_messages.pkl")  # pour recharger facilement plus tard
