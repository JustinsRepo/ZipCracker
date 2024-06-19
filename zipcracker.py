import pyzipper
import zlib
import threading

def open_password_protected_zip(file_path, password, path_extract):
    try:
        with pyzipper.AESZipFile(file_path, 'r') as zip_ref:
            zip_ref.setpassword(password.encode())
            zip_ref.extractall(path=path_extract)
            return True
    except (pyzipper.BadZipFile, zlib.error, RuntimeError, pyzipper.CryptoUnavailableError):
        return False

def crack_password(file_path, passwords, path_extract):
    for password in passwords:
        if open_password_protected_zip(file_path, password, path_extract):
            print(f"\nPassword cracked successfully. Password is: {password}")
            return True
    return False

if __name__ == "__main__":
    banner = '\033[91m' + '''
.___________. __  .___________.    ___      .__   __. 
|           ||  | |           |   /   \     |  \ |  | 
`---|  |----`|  | `---|  |----`  /  ^  \    |   \|  | 
    |  |     |  |     |  |      /  /_\  \   |  . `  | 
    |  |     |  |     |  |     /  _____  \  |  |\   | 
    |__|     |__|     |__|    /__/     \__\ |__| \__| 
              By: PixelRazer & Trace
    Contributers: zvrke
''' + '\033[0m'
    print(banner)

    file_path = input("Enter the location of the zip file: ")
    password_list_file = input("Enter the location of the file containing the list of passwords: ")
    path_extract = input("Directory where you want to extract the contents of the files to: ")

    with open(password_list_file, 'r', encoding='latin-1') as file:
        passwords = [password.strip() for password in file.readlines()]

    print(f"\nCracking password...\n")

    # Splitting passwords into chunks for multi-threading
    num_threads = 4
    password_chunks = [passwords[i:i + num_threads] for i in range(0, len(passwords), num_threads)]

    # Thread creation
    threads = []
    for chunk in password_chunks:
        thread = threading.Thread(target=crack_password, args=(file_path, chunk, path_extract))
        thread.start()
        threads.append(thread)

    # Thread joining
    for thread in threads:
        thread.join()

    print("\nPassword cracking completed.")
