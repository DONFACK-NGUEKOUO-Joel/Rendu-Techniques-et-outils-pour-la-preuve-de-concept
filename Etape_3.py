import pandas as pd
import networkx as nx

INPUT_FLOWS = "modbus_flows.pkl"
OUTPUT_TREES = "modbus_trees.pkl"

def load_flows():
    flows = pd.read_pickle(INPUT_FLOWS)
    return flows  # dict: flow_key -> list of messages (list of int)

def build_prefix_tree_for_flow(messages):
    """
    Construit un arbre de préfixes (prefix tree) pour une liste de messages.
    Chaque message est une liste d'octets (int 0-255).
    On retourne un graph NetworkX orienté + l'id du nœud racine.
    """
    G = nx.DiGraph()
    root = 0
    G.add_node(root, byte=None, count=0)  # racine : pas d'octet associé

    next_node_id = 1

    for msg in messages:
        current = root
        G.nodes[current]["count"] += 1  # ce nombre de messages passe par ce nœud

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

def build_trees_for_all_flows(flows):
    
    trees = {}
    for flow_key, messages in flows.items():
        print(f"Construction de l'arbre pour le flux {flow_key} (messages: {len(messages)})")
        G, root = build_prefix_tree_for_flow(messages)
        trees[flow_key] = (G, root)
    return trees

flows = load_flows()
trees = build_trees_for_all_flows(flows)

# Exemple d'inspection : 1er flux
first_flow = next(iter(trees))
G, root = trees[first_flow]
print("Premier flux :", first_flow)
print("Nombre de noeuds dans son arbre :", G.number_of_nodes())
print("Nombre d'arêtes dans son arbre :", G.number_of_edges())
print("Successeurs directs de la racine :",
    [(n, G.nodes[n].get("byte"), G.nodes[n].get("count")) for n in G.successors(root)][:10])

# Sauvegarde pour les phases suivantes (fusion / optimisation)
pd.to_pickle(trees, OUTPUT_TREES)
print("Sauvegardé dans", OUTPUT_TREES)
