# Just a simple network call

import asyncio
from common.base import run_payloads

# RAW request (from Burp Intruder) with placeholders like §1§, §2§... or §CODE§, §USER§
RAW_REQUEST = """
GET /filter?category=Pets HTTP/2
Host: 0a00003a0497538b804c08d6005b004e.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: https://0a00003a0497538b804c08d6005b004e.web-security-academy.net/
Cookie: session=VjncAOXHmKXGks4abbCV5N38OfOPePI8; TrackingId=eBPPhE534sOJOMao
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
TE: trailers
""".strip()

async def one_call():
    """A simple call. Returns the response"""

    # One request, no payload replaces
    raw_req = RAW_REQUEST
    result = await run_payloads(raw_req, [{}], lambda x: True)
    return result

async def main():
    result = await one_call()
    if result['status_code'] == 200:
        print(f"\n[>] Successful")
    else:
        print("\n[-] No valid payload found.")

if __name__ == "__main__":
    asyncio.run(main())