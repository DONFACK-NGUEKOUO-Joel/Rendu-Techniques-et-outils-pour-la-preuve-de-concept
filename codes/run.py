import os
from scapy.all import rdpcap, Raw
from collections import defaultdict, Counter
import numpy as np
#from sklearn.cluster import KMeans

########################################################################
# 1. EXTRACTION DES FLOWS
########################################################################

def extract_flows_from_pcap(filename):
    packets = rdpcap(filename)
    flows = []

    for pkt in packets:
        if Raw in pkt:
            flows.append(bytes(pkt[Raw].load))

    return flows


########################################################################
# 2. CONTRUCTION DES ARBRES GrAMeFFSI (VERSION SIMPLIFIÉE)
########################################################################

def build_tree_from_message(msg):
    """
    Crée un arbre très simple : une liste de nœuds sous forme de dictionnaires.
    Arbre linéaire : racine -> byte0 -> byte1 -> ...
    """
    tree = [{"id": 0, "label": "root", "children": list(range(1, len(msg)+1))}]
    for i, b in enumerate(msg):
        tree.append({
            "id": i+1,
            "label": ("CONST(%02X)" % b),
            "value": b,
            "children": []
        })
    return tree


########################################################################
# 3. FUSION DES ARBRES PAR SIMILARITÉ
########################################################################

def merge_trees(trees):
    """
    Fusion très simplifiée : on regroupe les nœuds ayant la même position.
    On rend CONST(x) si tous les messages ont la même valeur.
    Sinon BYTE(unk).
    """
    max_len = max(len(t) for t in trees)
    merged = []

    for pos in range(max_len):
        values = []
        for t in trees:
            if pos < len(t):
                label = t[pos]["label"]
                if label.startswith("CONST("):
                    val = int(label.split("(")[1].split(")")[0], 16)
                    values.append(val)

        if len(values) == 0:
            merged.append({"id": pos, "label": "BYTE(unk)", "value": None})
        else:
            if len(set(values)) == 1:
                merged.append({"id": pos, "label": f"CONST({values[0]:02X})", "value": values[0]})
            else:
                merged.append({"id": pos, "label": "BYTE(unk)", "value": None})

    return merged


########################################################################
# 4. ANALYSES AVANCÉES
########################################################################

def analyze_variance(all_messages):
    """
    Détecte les positions variables.
    """
    lengths = set(len(m) for m in all_messages)
    max_len = max(lengths)

    variances = []

    for i in range(max_len):
        vals = []
        for m in all_messages:
            if i < len(m):
                vals.append(m[i])

        if len(vals) > 1:
            var = np.var(vals)
        else:
            var = 0

        variances.append(var)

    return variances


def detect_ascii_fields(all_messages):
    """
    Détecte les positions où les bytes semblent ASCII.
    """
    ascii_positions = []

    for i in range(max(len(m) for m in all_messages)):
        chars = []
        for m in all_messages:
            if i < len(m):
                b = m[i]
                if 32 <= b <= 126:
                    chars.append(b)

        ratio = len(chars) / len(all_messages)
        if ratio > 0.7:
            ascii_positions.append(i)

    return ascii_positions


def detect_counters(all_messages):
    """
    Détecte des compteurs simples (incréments linéaires par position).
    """
    counters = []

    max_len = max(len(m) for m in all_messages)
    for i in range(max_len):
        series = []
        for m in all_messages:
            if i < len(m):
                series.append(m[i])

        if len(series) >= 3:
            diffs = np.diff(series)
            if np.all((diffs == diffs[0])):
                counters.append(i)

    return counters


def detect_bitfields(all_messages):
    """
    Si la variance est faible mais non nulle -> probablement flags.
    """
    bitfields = []
    max_len = max(len(m) for m in all_messages)

    for i in range(max_len):
        vals = []
        for m in all_messages:
            if i < len(m):
                vals.append(m[i])

        if 0 < np.var(vals) < 10:
            bitfields.append(i)

    return bitfields


########################################################################
# 5. VISUALISATION TEXTE DE LA STRUCTURE
########################################################################

def visualize_tree(tree, variances, ascii_pos, counters, bitfields):
    for n in tree:
        pos = n["id"]
        label = n["label"]

        extra = []
        if pos < len(variances) and variances[pos] > 0:
            extra.append("VAR")
        if pos in ascii_pos:
            extra.append("ASCII")
        if pos in counters:
            extra.append("COUNTER")
        if pos in bitfields:
            extra.append("BITFIELD")

        extra_txt = (" [" + ", ".join(extra) + "]") if extra else ""
        print(f"{pos:4d} : {label}{extra_txt}")


########################################################################
# 6. CLUSTERING DES MESSAGES
########################################################################

def cluster_messages(all_messages, n_clusters=3):
    """
    K-Means sur padding zéro.
    """
    max_len = max(len(m) for m in all_messages)
    mat = np.zeros((len(all_messages), max_len))

    for i, m in enumerate(all_messages):
        mat[i, :len(m)] = m

    km = KMeans(n_clusters=n_clusters, n_init='auto')
    labels = km.fit_predict(mat)

    clusters = defaultdict(list)
    for idx, lab in enumerate(labels):
        clusters[lab].append(all_messages[idx])

    return clusters


########################################################################
# 7. MAIN
########################################################################

if __name__ == "__main__":

    pcaps = ["captures1.pcap", "captures2.pcap"]
    all_messages = []

    print("[+] Chargement des captures…")
    for p in pcaps:
        if os.path.exists(p):
            print(f"[+] Chargement : {p}")
            msgs = extract_flows_from_pcap(p)
            all_messages.extend(msgs)
        else:
            print(f"[!] Fichier introuvable : {p}")

    print(f"\n[+] Total flows : {len(all_messages)}\n")

    # Construire les arbres individuels
    print("[+] Construction des arbres…")
    trees = [build_tree_from_message(m) for m in all_messages]
    print(f"[+] Generated {len(trees)} trees before merging\n")

    # Fusion
    merged_tree = merge_trees(trees)
    print("Merged tree structure:")
    for n in merged_tree:
        print(n["id"], n["label"])
    print("\n")

    # ANALYSES
    print("[+] Analyse avancée…")
    variances = analyze_variance(all_messages)
    ascii_pos = detect_ascii_fields(all_messages)
    counters = detect_counters(all_messages)
    bitfields = detect_bitfields(all_messages)

    print("[+] Visualisation de la structure combinée :\n")
    visualize_tree(merged_tree, variances, ascii_pos, counters, bitfields)

    # Clustering
    print("\n[+] Clustering des messages…")
    clusters = cluster_messages(all_messages, n_clusters=3)
    for k, v in clusters.items():
        print(f"Cluster {k}: {len(v)} messages")
