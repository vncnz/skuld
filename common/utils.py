import subprocess

def save_on_file(content: str, open_file: bool = False, filename='/tmp/output.txt'):
    """Salva il contenuto in /tmp e lo apre con il gestore di sistema (xdg-open)."""
    # ext = ".html" if is_html else ".txt"
    # with tempfile.NamedTemporaryFile("w", delete=False, suffix=ext, prefix="repeater_res_") as f:
    with open(filename, 'w') as f:
        f.write(content)
        temp_path = f.name

    print(f"\n[+] Saved response in: {temp_path}")

    if open_file:
        # xdg-open for default app
        try:
            subprocess.Popen(["xdg-open", temp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[-] Impossibile aprire xdg-open: {e}")