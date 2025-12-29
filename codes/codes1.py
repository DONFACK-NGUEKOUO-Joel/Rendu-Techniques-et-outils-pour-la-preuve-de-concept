# === grameffsi.py ===
from collections import defaultdict
import networkx as nx
from utils import is_printable, bytes_to_int_le

class GrAMeFFSI:
    def __init__(self, min_packets=2):
        self.min_packets = min_packets
        self.trees = []

    def process_flows(self, flows):
        for flow_packets in flows:
            if len(flow_packets) < self.min_packets:
                continue
            tree = self._build_tree_for_flow(flow_packets)
            self.trees.append(tree)
        return self.trees

    def _build_tree_for_flow(self, packets):
        G = nx.DiGraph()
        root = 0
        G.add_node(root, label="root")
        node_counter = 1
        ptrs = [0 for _ in packets]
        while any(ptr < len(p) for ptr, p in zip(ptrs, packets)):
            next_bytes = []
            for i, p in enumerate(packets):
                if ptrs[i] < len(p):
                    next_bytes.append(p[ptrs[i]])
                else:
                    next_bytes.append(None)
            if any(b is None for b in next_bytes):
                break
            if all(b == next_bytes[0] for b in next_bytes):
                G.add_node(node_counter, label=f"CONST({next_bytes[0]:02x})")
                G.add_edge(root, node_counter)
                for i in range(len(ptrs)):
                    ptrs[i] += 1
                node_counter += 1
                root = node_counter - 1
                continue
            is_len_prefixed = True
            lengths = []
            for i, p in enumerate(packets):
                if ptrs[i] < len(p):
                    L = p[ptrs[i]]
                    start = ptrs[i] + 1
                    end = start + L
                    if end <= len(p) and all(is_printable(chr(c)) for c in p[start:end]):
                        lengths.append(L)
                    else:
                        is_len_prefixed = False
                        break
                else:
                    is_len_prefixed = False
                    break
            if is_len_prefixed and len(lengths) > 0:
                G.add_node(node_counter, label=f"LENSTR(len={lengths[0]})")
                G.add_edge(root, node_counter)
                for i in range(len(ptrs)):
                    ptrs[i] += 1 + lengths[i]
                node_counter += 1
                root = node_counter - 1
                continue
            is_null_term = True
            n_lengths = []
            for i, p in enumerate(packets):
                start = ptrs[i]
                found = False
                for j in range(start, len(p)):
                    if p[j] == 0:
                        if all(is_printable(chr(c)) for c in p[start:j]):
                            n_lengths.append(j - start)
                            found = True
                        break
                if not found:
                    is_null_term = False
                    break
            if is_null_term and len(n_lengths) > 0:
                G.add_node(node_counter, label=f"NULLSTR(len={n_lengths[0]})")
                G.add_edge(root, node_counter)
                for i in range(len(ptrs)):
                    ptrs[i] += n_lengths[i] + 1
                node_counter += 1
                root = node_counter - 1
                continue
            if all(ptrs[i] + 4 <= len(packets[i]) for i in range(len(packets))):
                vals = [bytes_to_int_le(packets[i][ptrs[i]:ptrs[i]+4]) for i in range(len(packets))]
                rems = [len(packets[i]) - (ptrs[i] + 4) for i in range(len(packets))]
                if all(vals[i] == rems[i] or vals[i] == rems[i] - 1 for i in range(len(vals))):
                    G.add_node(node_counter, label=f"LEN4({vals[0]})")
                    G.add_edge(root, node_counter)
                    for i in range(len(ptrs)):
                        ptrs[i] += 4
                    node_counter += 1
                    root = node_counter - 1
                    continue
            G.add_node(node_counter, label="BYTE(unk)")
            G.add_edge(root, node_counter)
            for i in range(len(ptrs)):
                if ptrs[i] < len(packets[i]):
                    ptrs[i] += 1
            node_counter += 1
            root = node_counter - 1
        return G


# === utils.py ===
def is_printable(ch):
    return 32 <= ord(ch) <= 126

def bytes_to_int_le(bts):
    if len(bts) == 4:
        return int.from_bytes(bts, byteorder='little', signed=False)
    return None


# === evaluate.py ===
def correctness(inferred_msgs, true_msgs):
    if not inferred_msgs:
        return 0.0
    matched = sum(1 for m in inferred_msgs if m in true_msgs)
    return matched / len(inferred_msgs)

def conciseness(inferred_msgs, true_msgs):
    if not true_msgs:
        return float('inf')
    return len(inferred_msgs) / len(true_msgs)

def coverage(inferred_msgs, true_msgs):
    if not true_msgs:
        return 0.0
    covered = sum(1 for t in true_msgs if t in inferred_msgs)
    return covered / len(true_msgs)

def accuracy(pred_semantics, true_semantics):
    if not true_semantics:
        return 0.0
    matches = sum(1 for k,v in pred_semantics.items() if k in true_semantics and true_semantics[k]==v)
    return matches / len(true_semantics)

def adjusted_accuracy(pred_semantics, true_semantics):
    if not true_semantics:
        return 0.0
    base = accuracy(pred_semantics, true_semantics)
    fp = sum(1 for k in pred_semantics if k not in true_semantics)
    return max(0.0, base - fp * 0.01)


# === run.py ===
from grameffsi import GrAMeFFSI

def load_sample_flows():
    f1 = [b"\x01\x02hello\x00", b"\x01\x02world\x00"]
    f2 = [b"\x10\x00\x00\x00ABCDEF", b"\x10\x00\x00\x00ABCXYZ"]
    return [f1, f2]

def main():
    flows = load_sample_flows()
    g = GrAMeFFSI(min_packets=2)
    trees = g.process_flows(flows)
    print("Generated", len(trees), "trees")
    for i, t in enumerate(trees):
        print("Tree", i)
        for n, d in t.nodes(data=True):
            print(n, d.get("label"))

if __name__ == "__main__":
    main()
