# imports
import pyzipper
import bcrypt
import secrets
from pathlib import Path
import zlib
import time
import threading

def open_password_protected_zip(file_path, password, extraction_path):
    try:
        with pyzipper.AESZipFile(file_path, 'r') as zip_ref:
            # decrypt the zip file using the provided password
            zip_ref.setpassword(password.encode())
            # check if the zip file can be read successfully
            zip_ref.read(zip_ref.infolist()[0])
            # if no exception is raised, the password is correct
            zip_ref.extractall(path=extraction_path)
            # if the password is correct, extract the contents of the zipfile
            return True
    except (pyzipper.BadZipFile, zlib.error):
        # if an exception is raised, the password is incorrect or the zip file is invalid
        return False

def crack_password(passwords):
    success = False
    for password in passwords:
        password_hash = bcrypt.haspw(password.encode(), bcrypt.gensalt(secrets.token_bytes(16)) # 16 bit salt generation
        # For password hashing and verification
        if bcrypt.checkpw(password.encode(), password_hash):
            if open_password_protected_zip(file_path, password, extraction_path):
                success = True
                print(f"\nPassword cracked successfully. Password is: {password}")
                break #optionally, just exit(1) would work here.

    if not success:
        print("\nUnable to crack the password. Password not found.")

banner = '\033[91m' + '''
.___________. __  .___________.    ___      .__   __. 
|           ||  | |           |   /   \     |  \ |  | 
`---|  |----`|  | `---|  |----`  /  ^  \    |   \|  | 
    |  |     |  |     |  |      /  /_\  \   |  . `  | 
    |  |     |  |     |  |     /  _____  \  |  |\   | 
    |__|     |__|     |__|    /__/     \__\ |__| \__| 
              By: PixelRazer & Trace
    Contributers: [JustinsRepo, KittenGirl]
''' + '\033[0m'

print(banner)

file_path = input("Enter the location of the zip file: ")
password_list_file = input("Enter the location of the file containing the list of passwords: ")
extraction_path = input("Directory where you want to extract the contents of the files to: ")

file_path = Path(file_path).resolve(strict=True)
password_list_file = Path(password_list_file).resolve(strict=True)
extraction_path = Path(extraction_path).resolve()

if not extraction_path.is_dir():
    print("Invalid extraction path. Please provide a valid directory.")
    exit(1)

try:
    with open(password_list_file, 'r', encoding='latin-1') as file:
        passwords = [password.strip() for password in file.readlines()]
except Exception as openZexception:
    print(f"\nSomewhere goofed up: \n {openZexception}"+"\n"*10)
    exit(0)

print(f"\nCracking password...\n")

#splitting password threads
num_threads = 4
password_chunks = [passwords[i:i+num_threads] for i in range(0, len(passwords), num_threads)]

#thread creation
threads = []
for chunk in password_chunks:
    thread = threading.Thread(target=crack_password, args=(zip_file_path,chunk,extraction_path))
    thread.start()
    threads.append(thread)

#thread finish
for thread in threads:
    thread.join()
