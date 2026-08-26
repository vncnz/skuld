
# Skuld - ᛊᚲᚢᛚᛞ

A collection of modular Python scripts and HTTP/2 automation utilities designed for PortSwigger Web Security Academy labs and BSCP exam preparation.

Named after the Norn of what is to be revealed, Skuld provides lightweight async alternatives to Burp Suite Intruder/Repeater workflows for educational web security environments.

## About the name

In Norse mythology, Skuld is one of the three Norns (the goddesses of fate) who personifies the future, representing "that which shall be" or "debt". She uniquely serves as both a weaver of destiny alongside her sisters (Urd and Verdandi) and a battle-ready Valkyrie.

## Usage

1. Create venv

```bash
python -m venv /tmp/bf-env
source /tmp/bf-env/bin/activate
```

2. Install all

```bash
pip install "httpx[h2]"
pip install "httpx[http2]"
```

3. Execute this script

```bash
python [script].py
```

4. Exit and clear

```bash
deactivate
rm -rf /tmp/bf-env
```


## My progress in Accademy

### Completed

- Server-side vulnerabilities (Apprentice, the only one)
- Authentication vulnerabilities
- SQL injection
- API testing
- Path traversal
  
### Available

- Server-side request forgery (SSRF) attacks
- File upload vulnerabilities
- Cross-site request forgery (CSRF)
- Prototype pollution

- Web cache deception
- WebSockets vulnerabilities
- Clickjacking (UI redressing)
- GraphQL API vulnerabilities
- Cross-origin resource sharing (CORS)
- NoSQL injection
- Race conditions
- Web LLM attacks