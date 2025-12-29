from scapy.all import rdpcap, Packet
from typing import List, Dict, Any, Tuple
import os

# =========================================================
# I. STRUCTURES DE DONNÉES (Phase I)
# =========================================================

# Seuil pour la détection des types énumérés
ENUM_THRESHOLD = 10 

class FieldType:
    #"""Les 'couleurs' des nœuds, représentant la sémantique de champ inférée."""
    CONSTANT = 0        # Vert
    STRING = 1          # Cyan
    LENGTH = 2          # Bleu
    COUNTER = 3         # Violet
    ENUMERATED = 4      # Orange (nœud de branchement)
    VARIABLE = 5        # Noir/HVAR (Highly Variable - par défaut)
    SESSION_ID = 6      # Après la Phase III
    FLAG = 7            # Après la Phase III

class Node:
    #"""Représente un nœud dans l'arbre de format de message."""
    def _init_(self, offset: int, field_type: int, size: int, value: Any = None):
        self.offset = offset             # Position de début dans le message (en octets)
        self.field_type = field_type     # Sémantique de champ (FieldType)
        self.size = size                 # Taille du champ en octets
        self.value = value               # Valeur (pour CONSTANT ou le label d'une branche)
        self.children: List['Node'] = [] # Liste des nœuds enfants séquentiels
        self.branches: Dict[Any, 'Node'] = {} # Dict {valeur: sous-arbre} pour ENUMERATED

class StreamPacket:
    #"""Représente un paquet en cours de traitement dans un flux (session)."""
    def __init__(self, raw_data: bytes, original_packet=None):
        self.raw_data = raw_data          # Les octets bruts du paquet
        self.original_packet = original_packet
        self.current_offset = 0           # Pointeur dans la charge utile


# =========================================================
# I.b FONCTION DE CHARGEMENT PCAP (Intégration Scapy)
# =========================================================

def load_and_preprocess_pcap(pcap_file_path: str, protocol_layer: str = 'Raw') -> List[List[StreamPacket]]:
   # """
   # Charge un fichier .pcap, divise les paquets par flux (session) 
    #et extrait la charge utile binaire pour GrAMeFFSI.
   # """
    if not os.path.exists(pcap_file_path):
        print(f"Erreur: Le fichier {pcap_file_path} n'a pas été trouvé.")
        return []

    print(f"Chargement du fichier: {pcap_file_path}...")
    packets = rdpcap(pcap_file_path)
    sessions: Dict[Tuple, List[StreamPacket]] = {}

    for pkt in packets:
        # Simplification : vérification des couches nécessaires pour la session
        if 'IP' in pkt and ('TCP' in pkt or 'UDP' in pkt) and protocol_layer in pkt:
            
            # Détermination de la clé de flux canonique (pour regrouper les deux directions)
            ip_src = pkt['IP'].src
            ip_dst = pkt['IP'].dst
            proto = 'TCP' if 'TCP' in pkt else 'UDP'
            port_src = pkt[proto].sport
            port_dst = pkt[proto].dport
            
            key_tuple = tuple(sorted(((ip_src, port_src), (ip_dst, port_dst))))
            
            # Extraction de la charge utile
            payload = bytes(pkt[protocol_layer]) 
            
            if payload:
                stream_packet = StreamPacket(raw_data=payload, original_packet=pkt)
                sessions.setdefault(key_tuple, []).append(stream_packet)

    sessions_list = list(sessions.values())
    print(f"Fichier chargé. {len(sessions_list)} flux (sessions) identifiés.")
    return sessions_list


# =========================================================
# II. HEURISTIQUES ET UTILS (Phase II)
# =========================================================

def advance_pointers(packets: List[StreamPacket], length: int):
   # """Avance le pointeur de chaque paquet du sous-ensemble actuel."""
    for p in packets:
        p.current_offset += length

def create_node_and_link(parent: Node, packets: List[StreamPacket], type: int, size: int, value: Any = None) -> Node:
    #"""Crée un nœud, l'ajoute comme enfant du parent et retourne le nouveau nœud."""
    offset = packets[0].current_offset
    new_node = Node(offset, type, size, value)
    parent.children.append(new_node)
    return new_node

def get_distinct_values_at_offset(packets: List[StreamPacket]) -> set:
    #"""Retourne l'ensemble des octets distincts à l'offset actuel."""
    return set(p.raw_data[p.current_offset] for p in packets if p.current_offset < len(p.raw_data))


# Heuristique 1 : CONSTANT
def is_constant(packets: List[StreamPacket]) -> Tuple[bool, Any]:
   # """Test 1: Vérifie si le prochain octet est le même pour tous les paquets."""
    if not packets: 
        return False, None
    
    first_byte = packets[0].raw_data[packets[0].current_offset]
    is_const = all(p.current_offset < len(p.raw_data) and p.raw_data[p.current_offset] == first_byte for p in packets)
    
    return is_const, first_byte


# Heuristique 2 & 3 : STRING (Simplifiée)
def is_string_field(packets: List[StreamPacket]) -> Dict[str, Any] | None:
  
    #Test 2 & 3: Vérifie les patterns de chaînes de caractères (longueur-prefixe ou null-terminée).
    #(Implémentation simplifiée ici, l'article nécessite une vérification de caractères imprimables)
   
    # Ici, nous simulerons uniquement le pattern Longueur-Prefixe pour l'exemple.
    
    for p in packets:
        if p.current_offset >= len(p.raw_data): return None
        try:
            length = p.raw_data[p.current_offset]
            # Vérifier si la chaîne rentre dans le paquet restant
            if p.current_offset + 1 + length > len(p.raw_data):
                return None # Échec de lecture ou longueur invalide
        except IndexError:
            return None 
            
    # Si tous les paquets passent le test Longueur-Prefixe
    return {'size': length + 1} # Taille: octet de longueur (1) + données (length)


# (Les heuristiques LENGTH et COUNTER ne sont pas implémentées ici pour la concision)


# =========================================================
# II. LOGIQUE PRINCIPALE DE CONSTRUCTION (Phase II)
# =========================================================

def construct_tree_for_stream(packets: List[StreamPacket]) -> Node:
    
    #Construit l'arbre de format de message pour un seul flux (session) 
    #en utilisant les heuristiques séquentielles.

    # Création d'une racine temporaire pour l'initialisation
    root = Node(0, FieldType.VARIABLE, 0)
    
    # Worklist pour gérer l'exploration des branches (Depth-First Search)
    # Contient des tuples (parent_node, liste_paquets_restants)
    branches_to_process = [(root, packets)]
    
    print(f"  -> Démarrage de l'analyse avec {len(packets)} paquets.")

    while branches_to_process:
        parent_node, current_packets = branches_to_process.pop(0)

        # Filtrer les paquets qui sont déjà complètement analysés (fin de la charge utile)
        current_packets = [p for p in current_packets if p.current_offset < len(p.raw_data)]

        if not current_packets:
            continue

        # --- Test 1 : CONSTANT ---
        is_const, value = is_constant(current_packets)
        if is_const:
            new_node = create_node_and_link(parent_node, current_packets, FieldType.CONSTANT, size=1, value=value)
            advance_pointers(current_packets, 1)
            branches_to_process.append((new_node, current_packets))
            continue
            
        # --- Test 2/3 : STRING (Longueur-Prefixe/Null-Terminée) ---
        string_result = is_string_field(current_packets)
        if string_result:
            size = string_result['size']
            new_node = create_node_and_link(parent_node, current_packets, FieldType.STRING, size=size)
            advance_pointers(current_packets, size)
            branches_to_process.append((new_node, current_packets))
            continue

        # --- Test 6 : ENUMERATED (Branchement) ---
        distinct_values = get_distinct_values_at_offset(current_packets)
        num_distinct = len(distinct_values)

        if 1 < num_distinct <= ENUM_THRESHOLD:
            # Créer un nœud ENUMERATED pour symboliser le point de branchement
            enum_parent = create_node_and_link(parent_node, current_packets, FieldType.ENUMERATED, size=1)
            
            for value in distinct_values:
                # Filtrer les paquets pour créer une nouvelle sous-branche
                split_packets = [p for p in current_packets if p.raw_data[p.current_offset] == value]
                
                # Créer le nœud de branchement (qui est un CONSTANT avec la valeur d'énumération)
                branch_node = Node(split_packets[0].current_offset, FieldType.CONSTANT, 1, value=value)
                enum_parent.branches[value] = branch_node 
                
                advance_pointers(split_packets, 1) # Avancer le pointeur après l'octet énuméré
                branches_to_process.append((branch_node, split_packets))
            continue
        
        # --- Test 7 : VARIABLE (Highly variable) ---
        else:
            # Avancer d'un octet par défaut si aucun pattern n'est trouvé.
            new_node = create_node_and_link(parent_node, current_packets, FieldType.VARIABLE, size=1)
            advance_pointers(current_packets, 1)
            branches_to_process.append((new_node, current_packets))

    return root


# =========================================================
# III. EXÉCUTION (Intégration des captures)
# =========================================================

if __name__ == "__main__":
    
    # 1. Configuration
    # Ciblez la couche protocolaire dans Scapy qui contient la charge utile binaire de votre protocole.
    TARGET_LAYER = 'Raw' 
    CAPTURE_FILES = ["captures1.pcap", "captures2.pcap"]

    all_root_nodes_for_merging = []

    # 2. Chargement et Phase II pour chaque capture
    for filename in CAPTURE_FILES:
        print(f"\n--- DÉBUT DE L'ANALYSE DE {filename} ---")
        
        # Charger les flux du fichier
        list_of_streams = load_and_preprocess_pcap(filename, protocol_layer=TARGET_LAYER)
        
        # Exécuter la Phase II sur chaque flux
        for i, stream in enumerate(list_of_streams):
            print(f"  [Flux {i+1}/{len(list_of_streams)}] Construction de l'arbre...")
            root_node = construct_tree_for_stream(stream) 
            all_root_nodes_for_merging.append(root_node)

    print(f"\n--- RÉSULTAT DE LA PHASE II ---")
    print(f"Total de {len(all_root_nodes_for_merging)} arbres de format générés (prêts pour la Phase III).")
    
    # À ce stade, vous auriez besoin d'implémenter la fonction merge_all_trees (Phase III)
    # pour obtenir le modèle final consolidé.
    # final_model_root = merge_all_trees(all_root_nodes_for_merging)