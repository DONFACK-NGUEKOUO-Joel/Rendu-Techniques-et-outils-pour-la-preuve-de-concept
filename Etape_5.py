import pandas as pd
import networkx as nx
from collections import defaultdict, deque

INPUT_TREES_TAGGED = "modbus_trees_tagged.pkl"

def load_tagged_trees():
    trees = pd.read_pickle(INPUT_TREES_TAGGED)
    return trees  # dict: flow_key -> (G, root_id)

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

def summarize_constants_by_depth(G, root):
    depths = compute_depths(G, root)

    # Map: depth -> set of bytes constants à cette profondeur
    const_bytes_per_depth = defaultdict(set)
    # Map: depth -> bool (au moins un noeud rencontré à cette profondeur)
    has_node_at_depth = defaultdict(bool)

    for node, depth in depths.items():
        node_type = G.nodes[node].get("type")
        byte_val = G.nodes[node].get("byte")

        if depth == 0:
            continue  # racine

        has_node_at_depth[depth] = True

        if node_type == "constant" and byte_val is not None:
            const_bytes_per_depth[depth].add(byte_val)

    # Préparer un résumé ordonné par profondeur
    summary = []
    for depth in sorted(has_node_at_depth.keys()):
        const_bytes = const_bytes_per_depth.get(depth, set())
        if const_bytes:
            # On a au moins un octet constant à cette position
            label = "C"
        else:
            label = "V"
        # On formate les octets constants en hexadécimal
        const_hex = [f"0x{b:02X}" for b in sorted(const_bytes)]
        summary.append((depth, label, const_hex))

    return summary

def print_summary_for_flow(flow_key, G, root):
    print("Flux analysé :", flow_key)
    summary = summarize_constants_by_depth(G, root)
    print("Position | C/V | Octets constants (hex)")
    for depth, label, const_hex in summary:
        print(f"{depth:8d} |  {label}  | {', '.join(const_hex) if const_hex else '-'}")


trees_tagged = load_tagged_trees()

# Choix d'un flux à analyser : ici le premier par défaut
first_flow = next(iter(trees_tagged))
G, root = trees_tagged[first_flow]

print_summary_for_flow(first_flow, G, root)
