# check_solc.py
import solcx
installed = solcx.get_installed_solc_versions()
print("Installed versions:", installed)