import os
import win32com.client
from datetime import datetime

currentTime = datetime.now()
formatedTime = currentTime.strftime("%Y-%m-%d %H:%M:%S")

def set_restore_space(drive="C:", size_gb=20):
     os.system(f'vssadmin resize shadowstorage /For={drive} /On={drive} /MaxSize={size_gb}GB')

def delete_old_restore_points():
    os.system('vssadmin delete shadows /all /quiet')

def create_restore_point(description=f"Restore Point:{formatedTime}"):
    try:
        os.system(f'wmic.exe /Namespace:\\\\root\\default Path SystemRestore Call CreateRestorePoint "{description}", 100, 7')
        print(f"[+] Created restore point: {description}")
    except Exception as e:
        print(f"[!] Failed to create restore point: {e}")

def main():
    print("[*] Setting restore point storage limit...")
    set_restore_space()

    print("[*] Deleting old restore points...")
    delete_old_restore_points()

    print("[*] Creating new restore point...")
    create_restore_point("Python Automated Restore Point")

    print("[+] Task complete.")

if __name__ == "__main__":
    main()

# test