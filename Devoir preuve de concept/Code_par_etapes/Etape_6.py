import pandas as pd
import networkx as nx
from collections import deque

FLOWS_PICKLE = "modbus_flows.pkl"
TREES_TAGGED_PICKLE = "modbus_trees_tagged.pkl"

OUTPUT_GLOBAL_PICKLE = "modbus_global_tree.pkl"
OUTPUT_GLOBAL_CSV = "modbus_global_nodes.csv"

THRESHOLD = 0.95

def load_flows():
    return pd.read_pickle(FLOWS_PICKLE)  

def build_global_tree(flows):
    
    G = nx.DiGraph()
    root = 0
    G.add_node(root, byte=None, count=0)

    next_node_id = 1

    for flow_key, messages in flows.items():
        print(f"Ajout des messages du flux {flow_key} (messages: {len(messages)})")
        for msg in messages:
            current = root
            G.nodes[current]["count"] += 1

            for b in msg:
                # Chercher un enfant avec cet octet
                child = None
                for succ in G.successors(current):
                    if G.nodes[succ].get("byte") == b:
                        child = succ
                        break

                if child is None:
                    child = next_node_id
                    next_node_id += 1
                    G.add_node(child, byte=b, count=0)
                    G.add_edge(current, child)

                current = child
                G.nodes[current]["count"] += 1

    return G, root

def mark_node_types(G, root, threshold=THRESHOLD):
    G.nodes[root]["type"] = "root"
    G.nodes[root]["ratio"] = 1.0

    for parent, child in G.edges():
        parent_count = G.nodes[parent].get("count", 0)
        child_count = G.nodes[child].get("count", 0)

        if parent_count == 0:
            ratio = 0.0
        else:
            ratio = child_count / parent_count

        G.nodes[child]["ratio"] = ratio
        if ratio >= threshold:
            G.nodes[child]["type"] = "constant"
        else:
            G.nodes[child]["type"] = "variable"

def compute_depths(G, root):
    depths = {root: 0}
    queue = deque([root])

    while queue:
        current = queue.popleft()
        current_depth = depths[current]
        for child in G.successors(current):
            if child not in depths:
                depths[child] = current_depth + 1
                queue.append(child)

    return depths

def export_global_tree(G, root, csv_path):
    depths = compute_depths(G, root)
    rows = []

    for node in G.nodes():
        data = G.nodes[node]
        rows.append({
            "node_id": node,
            "depth": depths.get(node, -1),
            "byte": data.get("byte"),
            "count": data.get("count"),
            "ratio": data.get("ratio"),
            "type": data.get("type"),
        })

    df = pd.DataFrame(rows)
    df.sort_values(by=["depth", "node_id"], inplace=True)
    df.to_csv(csv_path, index=False)
    print(f"Arbre global exporté dans {csv_path}")


flows = load_flows()

print("Construction de l'arbre global...")
G_global, root_global = build_global_tree(flows)
print("Nombre de noeuds dans l'arbre global :", G_global.number_of_nodes())
print("Nombre d'arêtes dans l'arbre global :", G_global.number_of_edges())

print("Marquage constant/variable sur l'arbre global...")
mark_node_types(G_global, root_global, THRESHOLD)

# Inspection rapide de la profondeur 1
depths = compute_depths(G_global, root_global)
first_level = [(n, G_global.nodes[n].get("byte"),
                G_global.nodes[n].get("count"),
                round(G_global.nodes[n].get("ratio", 0.0), 3),
                G_global.nodes[n].get("type"))
                for n in G_global.nodes()
                if depths.get(n, -1) == 1]
print("Niveau 1 (juste après la racine) :")
for entry in first_level[:10]:
    print(entry)

# Sauvegarde pour réutilisation éventuelle
pd.to_pickle((G_global, root_global), OUTPUT_GLOBAL_PICKLE)
print("Arbre global sauvegardé dans", OUTPUT_GLOBAL_PICKLE)

# Export CSV lisible
export_global_tree(G_global, root_global, OUTPUT_GLOBAL_CSV)
