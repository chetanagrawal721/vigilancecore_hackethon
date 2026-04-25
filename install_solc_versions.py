# save as install_solc_versions.py and run it once
import solcx

versions = [
    "0.4.11", "0.4.12", "0.4.13", "0.4.14", "0.4.15",
    "0.4.16", "0.4.17", "0.4.18", "0.4.19", "0.4.20",
    "0.4.21", "0.4.22", "0.4.23", "0.4.24", "0.4.25",
    "0.5.0",  "0.5.1",  "0.5.2",  "0.5.3",  "0.5.4",
    "0.5.5",  "0.5.6",  "0.5.7",  "0.5.8",  "0.5.9",
    "0.5.10", "0.5.11", "0.5.12", "0.5.13", "0.5.14",
    "0.5.16", "0.5.17",
    "0.6.0",  "0.6.1",  "0.6.2",  "0.6.6",  "0.6.12",
    "0.7.0",  "0.7.6",
    "0.8.0",  "0.8.4",  "0.8.7",  "0.8.10", "0.8.17",
    "0.8.20",
]

for v in versions:
    try:
        print(f"Installing solc {v}...")
        solcx.install_solc(v)
        print(f"  ✅ {v} done")
    except Exception as e:
        print(f"  ❌ {v} failed: {e}")

print("\nAll done!")
print("Installed:", solcx.get_installed_solc_versions())