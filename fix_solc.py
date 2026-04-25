import subprocess
from pathlib import Path

binary = Path.home() / ".solcx" / "solc-v0.8.21"

# Unblock the original file in-place
r = subprocess.run(
    ["powershell", "-NoProfile", "-Command", f"Unblock-File '{binary}'"],
    capture_output=True, text=True
)
print("Unblock:", r.returncode, r.stderr.strip() or "OK")

# Test direct execution — no .exe copy needed
r = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
print("solc version:", r.stdout.strip() or r.stderr.strip())
print("returncode  :", r.returncode)
