# === model_merging.py ===
import networkx as nx

def merge_trees(trees):
    """
    Fusionne plusieurs arbres de messages (networkx DiGraphs) en un seul arbre général.
    Heuristique simple : fusionner les noeuds ayant le même label et même parent.
    """
    if not trees:
        return None

    merged = nx.DiGraph()
    merged.add_node(0, label="root")  # racine unique
    node_counter = 1
    path_map = {}  # (parent_id, label) -> node_id dans merged

    for t in trees:
        # parcours tous les chemins simples de la racine jusqu'au dernier noeud
        paths = nx.all_simple_paths(t, source=0, target=max(t.nodes))
        for path in paths:
            parent = 0
            for node in path[1:]:  # ignorer la racine
                # Utiliser le label de l'arbre courant (t) au lieu de trees[0]
                label = t.nodes[node].get("label", "UNK")
                key = (parent, label)
                if key in path_map:
                    nid = path_map[key]
                else:
                    nid = node_counter
                    merged.add_node(nid, label=label)
                    merged.add_edge(parent, nid)
                    path_map[key] = nid
                    node_counter += 1
                parent = nid

    return merged


def print_tree(tree):
    """
    Affiche les noeuds et étiquettes du graphe fusionné.
    """
    for n, d in tree.nodes(data=True):
        print(n, d.get("label"))

def infer_field_semantics(tree):
    """
    Infère les sémantiques des champs à partir des labels des noeuds.
    Renvoie un dictionnaire {node_id: semantic}.
    """
    semantics = {}
    for node, data in tree.nodes(data=True):
        label = data.get("label", "")
        if label.startswith("CONST"):
            semantics[node] = "Constant"
        elif label.startswith("NULLSTR"):
            semantics[node] = "Null String"
        elif label.startswith("BYTE"):
            semantics[node] = "Byte"
        else:
            semantics[node] = "Unknown"
    return semantics