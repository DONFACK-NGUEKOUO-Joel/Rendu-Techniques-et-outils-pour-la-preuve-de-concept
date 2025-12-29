import os
import numpy as np
import networkx as nx
from scapy.all import rdpcap, TCP, Raw
from collections import defaultdict, Counter
import matplotlib.pyplot as plt

# Étape 1 : Charger la capture
def load_packets(captures):
    return rdpcap(captures)


# Charger les paquets à partir du fichier pcap
packets = load_packets('C:\ENS_Paris_Saclay')
# Afficher le nombre de paquets chargés
print(f"{len(packets)} paquets chargés.")
# Vérifier le chargement
print(f"{len(packets)} paquets chargés.")



# Étape 2 : Extraire chargements utiles
def extract_payloads(packets):
    payloads = []
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            payloads.append(bytes(pkt[Raw].load))
    return payloads

# Étape 3 : Segmenter les messages (par longueur ou heuristiques)
def segment_messages(payloads):
    # Fonction simple : regrouper par longueur
    message_types = defaultdict(list)
    for payload in payloads:
        message_types[len(payload)].append(payload)
    return message_types

# Étape 4 : Calculer une distance entre deux messages
def message_similarity(msg1, msg2):
    # Pad les plus courts
    length = max(len(msg1), len(msg2))
    msg1_padded = msg1.ljust(length, b'\0')
    msg2_padded = msg2.ljust(length, b'\0')
    # Distance de Hamming simple
    diff = sum(c1 != c2 for c1, c2 in zip(msg1_padded, msg2_padded))
    return diff

# Étape 5 : Construire un graphe basé sur la similarité
def build_relation_graph(messages, threshold=5):
    G = nx.Graph()
    n = len(messages)

    for i in range(n):
        G.add_node(i, message=messages[i])

    for i in range(n):
        for j in range(i + 1, n):
            dist = message_similarity(messages[i], messages[j])
            if dist <= threshold:
                G.add_edge(i, j, weight=dist)

    return G

# Étape 6 : Clustering
def cluster_messages(G):
    clusters = list(nx.community.greedy_modularity_communities(G))
    return clusters

# Étape 7 : Inférence simplifiée
def infer_fields_from_cluster(messages):
    prefix_candidates = [m[:4] for m in messages if len(m) >= 4]
    possible_constants = Counter(prefix_candidates).most_common(1)
    constant_prefix = possible_constants[0][0] if possible_constants else None

    lengths = [len(m) for m in messages]
    length_counts = Counter(lengths)
    constant_length = length_counts.most_common(1)[0][0]

    return {
        'constant_prefix': constant_prefix,
        'constant_length': constant_length,
        'sample_messages': messages[:5]
    }