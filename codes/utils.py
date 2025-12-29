# === utils.py ===
def is_printable(ch):
    return 32 <= ord(ch) <= 126

def bytes_to_int_le(bts):
    if len(bts) == 4:
        return int.from_bytes(bts, byteorder='little', signed=False)
    return None