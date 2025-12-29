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

