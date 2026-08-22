
CONCURRENCY_LIMIT = 1
PRINT_OUTPUT_PREVIEW = False
SAVE_OUTPUT_TO_FILE = False

# --- PARSER & ENGINE ---

from common.utils import save_on_file
import asyncio
import httpx


def parse_raw_request(raw_text: str):
    """Build request (url, headers e body) from RAW string."""
    lines = raw_text.splitlines()
    method, path, _ = lines[0].strip().split()
    
    headers = {}
    body_lines = []
    is_body = False
    
    for line in lines[1:]:
        if line == "":
            is_body = True
            continue
        if is_body:
            body_lines.append(line)
        else:
            key, value = line.split(":", 1)
            if key.strip().lower() != "content-length":
                headers[key.strip()] = value.strip()
                
    host = headers.get("Host", "")
    url = f"https://{host}{path}"
    body = "\n".join(body_lines)
    
    return method, url, headers, body

def inject_payloads(raw_template: str, payload_dict: dict) -> str:
    """Dynamically replaces all placeholders in the template"""
    result = raw_template
    for placeholder, value in payload_dict.items():
        result = result.replace(placeholder, str(value))
    return result

async def test_code(client, semaphore, method, url, headers, body_template, payload_dict, stop_event, check_victory):
    if stop_event.is_set():
        return

    async with semaphore:
        # Dynamic body replace
        body = inject_payloads(body_template, payload_dict)
        
        # Dynamic headers replace (ex. Cookie or X-Forwarded-For)
        req_headers = {
            k: inject_payloads(v, payload_dict) for k, v in headers.items()
        }

        try:
            response = await client.request(
                method=method,
                url=url,
                headers=req_headers,
                content=body,
                follow_redirects=False # IMPORTANT if you need to check the return code 302
            )

            # Victory condition
            if check_victory(response):
                stop_event.set()
                result = {
                    "payload": payload_dict,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "http_version": response.http_version,
                    "reason": response.reason_phrase,
                    "text_preview": response.text[:100] if PRINT_OUTPUT_PREVIEW else None,
                    "full_text": response.text,
                    "total_seconds": response.elapsed.total_seconds()
                }

                if PRINT_OUTPUT_PREVIEW:
                    print(f"\n[+] Valid response (HTTP {response.status_code})!")
                    print(f"[+] Valid payload: {payload_dict}")
                    print("\n" + response.text[:100])
                    if len(response.text) > 100:
                        print("\n[... Output truncated ...]")

                if SAVE_OUTPUT_TO_FILE:
                    full_output = f"HTTP/{response.http_version} {response.status_code} {response.reason_phrase}\n"
                    full_output += "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                    full_output += "\n\n" + response.text
                    save_on_file(full_output, filename='/tmp/brute.html')

                return result
                
        except Exception as ex:
            print(ex)
            pass

async def run_payloads(raw_req, payload_iterable, check_victory):
    """Run payloads from a generator/iterable and return the first successful result."""
    method, url, headers, body_template = parse_raw_request(raw_req)
    # print(f"[*] Inizio fuzzer su {url}...")

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    stop_event = asyncio.Event()

    limits = httpx.Limits(max_connections=CONCURRENCY_LIMIT, max_keepalive_connections=CONCURRENCY_LIMIT)
    async with httpx.AsyncClient(http2=True, limits=limits, verify=False, timeout=30.0) as client:
        # tasks = []

        # Default behavior: run sequentially (useful for interactive multi-step attacks)
        for payload_dict in payload_iterable:
            res = await test_code(client, semaphore, method, url, headers, body_template, payload_dict, stop_event, check_victory)
            if res:
                return res

    return None