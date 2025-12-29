import pandas as pd

INPUT_PICKLE = "modbus_messages.pkl"
OUTPUT_PICKLE = "modbus_flows.pkl"

def load_messages():
    df = pd.read_pickle(INPUT_PICKLE)
    # On trie un peu pour avoir un ordre stable (optionnel)
    df = df.sort_values(by=["flow", "length"]).reset_index(drop=True)
    return df

def group_by_flow(df):
    flows = {}

    for _, row in df.iterrows():
        flow_key = row["flow"]          # tuple (src_ip, sport, dst_ip, dport)
        payload = row["payload"]        # type bytes
        if flow_key not in flows:
            flows[flow_key] = []
        # Chaque message est une liste d'octets, ce que l’algorithme considère comme une "séquence"
        flows[flow_key].append(list(payload))

    return flows


df = load_messages()
flows = group_by_flow(df)

print("Nombre de flux trouvés :", len(flows))
# Affichage d'exemple : 1er flux, 1er message (tronqué)
first_flow = next(iter(flows))
print("Premier flux :", first_flow)
print("Nombre de messages dans ce flux :", len(flows[first_flow]))
print("Premier message (longueur) :", len(flows[first_flow][0]))
print("Premiers octets :", flows[first_flow][0][:16])

# Sauvegarde pour les étapes suivantes (construction des arbres)
pd.to_pickle(flows, OUTPUT_PICKLE)
print("Sauvegardé dans", OUTPUT_PICKLE)
