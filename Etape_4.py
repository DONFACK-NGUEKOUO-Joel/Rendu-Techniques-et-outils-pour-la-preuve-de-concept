import pandas as pd
import networkx as nx

INPUT_TREES = "modbus_trees.pkl"
OUTPUT_TREES = "modbus_trees_tagged.pkl"

THRESHOLD = 0.95  # seuil pour considérer un octet comme constant

def load_trees():
    trees = pd.read_pickle(INPUT_TREES)
    return trees  

def mark_node_types(G, root, threshold=THRESHOLD):
   
    # La racine ne représente pas un octet concret
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

def process_all_trees(trees, threshold=THRESHOLD):
    for flow_key, (G, root) in trees.items():
        print(f"Marquage des noeuds pour le flux {flow_key}")
        mark_node_types(G, root, threshold)
    return trees


trees = load_trees()
trees_tagged = process_all_trees(trees, THRESHOLD)

# Exemple d'inspection sur le premier flux
first_flow = next(iter(trees_tagged))
G, root = trees_tagged[first_flow]
print("Premier flux :", first_flow)
print("Exemples de successeurs de la racine avec types :")
examples = []
for child in G.successors(root):
    node_data = G.nodes[child]
    examples.append(
        (child, node_data.get("byte"), node_data.get("count"),
         round(node_data.get("ratio", 0.0), 3),
         node_data.get("type"))
        )
    if len(examples) >= 10:
        break
    for e in examples:
        print(e)

    # Sauvegarde
    pd.to_pickle(trees_tagged, OUTPUT_TREES)
    print("Sauvegardé dans", OUTPUT_TREES)
