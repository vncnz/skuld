
# Skuld - ᛊᚲᚢᛚᛞ

A collection of modular Python scripts and HTTP/2 automation utilities designed for PortSwigger Web Security Academy labs and BSCP exam preparation.

Named after the Norn of what is to be revealed, Skuld provides lightweight async alternatives to Burp Suite Intruder/Repeater workflows for educational web security environments.

## About the name

In Norse mythology, Skuld is one of the three Norns (the goddesses of fate) who personifies the future, representing "that which shall be" or "debt". She uniquely serves as both a weaver of destiny alongside her sisters (Urd and Verdandi) and a battle-ready Valkyrie.

## Usage

1. Create venv

```bash
python -m venv env
source env/bin/activate
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

4. Exit and clear   (if you need to)

```bash
deactivate
rm -rf env
```


## My progress in Accademy

### Completed

- Server-side vulnerabilities (Apprentice, the only one)
- Authentication vulnerabilities
- SQL injection
- API testing
- Path traversal
- File upload vulnerabilities
- Server-side request forgery (SSRF) attacks

### Available

- NoSQL injection

- Race conditions
- GraphQL API vulnerabilities
- Prototype pollution

- Cross-site request forgery (CSRF)
- Cross-origin resource sharing (CORS)
- Clickjacking (UI redressing)
- WebSockets vulnerabilities

- Web cache deception
- Web LLM attacks
