# --- PAYLOAD GENERATORS ---

def generate_otps(length=4):
    """Generate zero-padded numbers"""
    for i in range(10**length):
        yield f"{i:0{length}d}"

def generate_wordlist(file_path):
    """Read a wordlist line by line"""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.strip()

def generate_alphanumeric (length=1, lower=True, upper=True, digits=True):
    """Generate alphanumeric strings of a given length."""
    import itertools
    import string
    chars = ""
    if lower:
        chars += string.ascii_lowercase
    if upper:
        chars += string.ascii_uppercase
    if digits:
        chars += string.digits

    for item in itertools.product(chars, repeat=length):
        yield ''.join(item)