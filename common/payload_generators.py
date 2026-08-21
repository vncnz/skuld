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

def generate_payloads_examples():
    """
    Change this function depending on your needs.
    Returns something like this: {"§PLACEHOLDER§": "VALUE"}
    """

    import string

    # One-shot payload (no placeholders)
    # return [{}]

    for pos in range(1, 21):

        for l in string.ascii_lowercase:
            yield {"§LETTER§": l, "§POS§": pos}
        for l in string.ascii_uppercase:
            yield {"§LETTER§": l, "§POS§": pos}
        for n in range(10):
            yield {"§LETTER§": str(n), "§POS§": pos}

    # for n in range(2,30):
    #    yield {"§len§": n}
    
    # EXAMPLE 1: Single payload (4-digits OTP)
    #for otp in generate_otps(length=4):
    #    yield {"§CODE§": otp}

    # EXAMPLE 2: Multi-payload / Cluster Bomb (Username + Password)
    # usernames = ["admin", "carlos", "wiener"]
    # passwords = generate_wordlist("passwords.txt")
    # for user, pwd in itertools.product(usernames, passwords):
    #     yield {"§USER§": user, "§PASS§": pwd}

    # EXAMPLE 3: Pitchfork (Coupled values 1:1)
    # for user, pwd in zip(users_list, pass_list):
    #     yield {"§USER§": user, "§PASS§": pwd}