import sys
import os
from cryptography.fernet import Fernet

def load_key(key_path):
    """Load the encryption key from a file."""
    try:
        with open(key_path, 'rb') as f:
            return f.read()
    except Exception as e:
        print('\n[Error] Unable to load key:', e)
        return None

def generate_key(key_dir, key_name):
    """Generate a new encryption key and save it to a file."""
    key = Fernet.generate_key()
    if not key_dir.endswith('/'):
        key_dir += '/'

    key_file = os.path.join(key_dir, key_name + '.vaultkey')
    try:
        with open(key_file, 'wb') as f:
            f.write(key)
        input(f'\n[Success] Key "{key_file}" generated! Press <ENTER> to return...')
    except Exception as e:
        print('\n[Error] Unable to generate key:', e)

def encrypt_files(key_path, dir_path):
    """Encrypt all files in the specified directory."""
    key = load_key(key_path)
    if not key:
        return

    for root, dirs, files in os.walk(dir_path):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                if not file.endswith('.vault'):
                    fernet = Fernet(key)
                    with open(file_path, 'rb') as f:
                        encrypted_data = fernet.encrypt(f.read())
                    with open(file_path, 'wb') as f:
                        f.write(encrypted_data)
                    new_path = os.path.join(root, file + '.vault')
                    os.rename(file_path, new_path)
                    print(f' [Encrypted] {file_path}')
            except Exception as e:
                print(f' [Error] Unable to encrypt {file_path}: {e}')
    
    input('\n[Success] Files have been encrypted! Press <ENTER> to return...\n')

def decrypt_files(key_path, dir_path):
    """Decrypt all files in the specified directory."""
    key = load_key(key_path)
    if not key:
        return

    for root, dirs, files in os.walk(dir_path):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                if file.endswith('.vault'):
                    fernet = Fernet(key)
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                        decrypted_data = fernet.decrypt(encrypted_data)
                    with open(file_path, 'wb') as f:
                        f.write(decrypted_data)
                    new_path = os.path.join(root, file[:-6])  # Remove '.vault'
                    os.rename(file_path, new_path)
                    print(f' [Decrypted] {file_path}')
            except Exception as e:
                print(f' [Error] Unable to decrypt {file_path}: {e}')
    
    input('\n[Success] Files have been decrypted! Press <ENTER> to return...\n')

def main():
    banner = '''
  __      __             _______  ______  _______   ______
 /  \\    /  \\           /  __   \\/  __  \\/  __   \\ /  __  \\
 \\   \\/\\/   /  VaultSecure  |  |_/  /|  |_/  /|  |_/  /|  |  
  \\        /    Protect |   __/  |   __/ |   __/ |   __/   
   \\__/\\  /   Your Data |  |     |  |    |  |    |  |      
        \\/   Securely   |__|     |__|    |__|    |__|     

 <1> Generate a new encryption key
 <2> Decrypt a folder
 <3> Encrypt a folder
 <4> Exit VaultSecure
'''
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen based on OS
        print(banner)
        
        try:
            option = int(input(' Choose an option: '))
            print('\n')
            if option == 1:
                key_dir = input(' Directory to save key (e.g., /home/user): ')
                key_name = input(' Key name (e.g., "my_secret_key"): ')
                generate_key(key_dir, key_name)
            elif option in [2, 3]:
                key_path = input(' Path to the key file (e.g., /home/user/mykey.vaultkey): ')
                dir_path = input(f' Directory to {"decrypt" if option == 2 else "encrypt"} (e.g., /home/user/files): ')
                if option == 2:
                    decrypt_files(key_path, dir_path)
                else:
                    encrypt_files(key_path, dir_path)
            elif option == 4:
                break
            else:
                print(' [Error] Invalid option. Please try again.')
        except KeyboardInterrupt:
            print('\n [Info] Exiting VaultSecure...')
            break
        except Exception as e:
            print(f' [Error] {e}')
    
    sys.exit('\n\n[Info] Thank you for using VaultSecure! Stay safe.\n')

if __name__ == "__main__":
    main()
