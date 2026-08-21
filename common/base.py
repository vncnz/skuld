# --- PARSER & ENGINE ---

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
    """Sostituisce dinamicamente tutti i segnaposto presenti nel template."""
    result = raw_template
    for placeholder, value in payload_dict.items():
        result = result.replace(placeholder, str(value))
    return result