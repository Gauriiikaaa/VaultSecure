import sys
import os
import shutil
import logging
import getpass
import hashlib
import json
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

class VaultSecure:
    def __init__(self):
        # Change base directory to your specified path
        self.base_dir = r"C:\Users\Gaurika\Desktop\pythoncodes\vaultsecure"
        self.setup_logging()
        self.config_file = os.path.join(self.base_dir, "config.json")
        self.load_config()

    def setup_logging(self):
        """Configure logging for the application."""
        log_dir = os.path.join(self.base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"vaultsecure_{datetime.now().strftime('%Y%m%d')}.log")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def load_config(self):
        """Load or create configuration file."""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {
                "recent_directories": [],
                "max_recent_dirs": 5,
                "backup_enabled": True,
                "backup_location": os.makedirs(os.path.join(self.base_dir, "backups"), exist_ok=True),
                "key_directory": os.path.join(self.base_dir, "keys")
            }
            self.save_config()



    def save_config(self):
        """Save configuration to file."""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple:
        """Generate an encryption key from a password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def create_backup(self, file_path: str):
        """Create a backup of a file before encryption/decryption."""
        if not self.config["backup_enabled"]:
            logging.info("Backup is disabled in the configuration.")
            return

        backup_dir = Path(self.config["backup_location"])
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = Path(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{file_path.name}_{timestamp}.backup"
        logging.info(f"Attempting to create backup for: {file_path}")
        try:
            shutil.copy2(file_path, backup_path)
        except Exception as e:
            logging.error(f"Error creating backup: {e}")

        logging.info(f"Created backup: {backup_path}")

    def load_key(self, key_path: str, password: str = None):
        """Load the encryption key from a file, optionally protected by password."""
        try:
        # Check if file exists
            if not os.path.exists(key_path):
                logging.error(f"Key file not found: {key_path}")
                return None

        # Check file size
            if os.path.getsize(key_path) == 0:
                logging.error("Key file is empty")
                return None

        # Try to open and read the file
            with open(key_path, 'rb') as f:
                try:
                    key_data = json.load(f)
                    logging.info("Successfully loaded key data")
                except json.JSONDecodeError as e:
                    logging.error(f"Invalid key file format: {e}")
                    return None

        # Check if password is required
            if password and key_data.get('password_protected'):
                try:
                    key, _ = self.derive_key_from_password(
                        password, 
                        base64.b64decode(key_data['salt'])
                    )
                    return key
                except Exception as e:
                    logging.error(f"Error deriving key from password: {e}")
                    return None

        # Return the key
            return key_data['key'].encode()

        except Exception as e:
            logging.error(f"Unable to load key: {e}")
            return None

    def generate_key(self, key_dir: str, key_name: str, password: str = None):
        """Generate a new encryption key and save it to a file."""
        key = Fernet.generate_key()
        key_dir = Path(key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)
        
        key_data = {'key': key.decode()}
        
        if password:
            derived_key, salt = self.derive_key_from_password(password)
            key_data.update({
                'password_protected': True,
                'salt': base64.b64encode(salt).decode(),
                'key': derived_key.decode()
            })
        
        key_file = key_dir / f"{key_name}.vaultkey"
        try:
            with open(key_file, 'w') as f:
                json.dump(key_data, f)
            logging.info(f"Generated key: {key_file}")
            return True
        except Exception as e:
            logging.error(f"Unable to generate key: {e}")
            return False

    def get_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def process_files(self, key_path: str, dir_path: str, encrypt: bool = True, password: str = None):
            """Process (encrypt/decrypt) files in the specified directory."""
            key = self.load_key(key_path, password)
            if not key:
                logging.error("Failed to load key")
                return False

            dir_path = Path(dir_path)
            if not dir_path.exists():
                logging.error(f"Directory not found: {dir_path}")
                return False
        
            logging.info(f"Processing directory: {dir_path}")
            fernet = Fernet(key)
    
            # Add to recent directories
            if str(dir_path) not in self.config["recent_directories"]:
                self.config["recent_directories"].insert(0, str(dir_path))
                self.config["recent_directories"] = self.config["recent_directories"][:self.config["max_recent_dirs"]]
                self.save_config()

            files_processed = 0
            allowed_extensions = ['.txt', '.doc']  # List of allowed file types

            for file_path in dir_path.rglob('*'):
                if not file_path.is_file():
                    continue

            # Only process .txt and .doc files
                if file_path.suffix not in allowed_extensions:
                    logging.info(f"Skipping unsupported file type: {file_path}")
                    continue

                logging.info(f"Found file: {file_path}")
                try:
                    if encrypt and not file_path.suffix == '.vault':
                        logging.info(f"Attempting to encrypt: {file_path}")
                        self._encrypt_file(file_path, fernet)
                        files_processed += 1
                    elif not encrypt and file_path.suffix == '.vault':
                        logging.info(f"Attempting to decrypt: {file_path}")
                        self._decrypt_file(file_path, fernet)
                        files_processed += 1
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")

            logging.info(f"Processed {files_processed} files")
            return files_processed > 0

    

    def _encrypt_file(self, file_path: Path, fernet: Fernet):
        """Encrypt a single file."""
        try:
            # Create backup before encryption
            self.create_backup(file_path)
            
            # Calculate original file hash
            original_hash = self.get_file_hash(file_path)
            
            # Read the file in binary mode
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt the data
            encrypted_data = fernet.encrypt(file_data)
            
            # Create encrypted file with .vault extension
            encrypted_file = file_path.with_suffix(file_path.suffix + '.vault')
            
            # Write the encrypted data in binary mode
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Remove original file
            os.remove(file_path)
            logging.info(f"Encrypted: {file_path}")
            
        except Exception as e:
            logging.error(f"Encryption failed for {file_path}: {e}")
            raise

    def _decrypt_file(self, file_path: Path, fernet: Fernet):
        """Decrypt a single file."""
        try:
            # Create backup before decryption
            self.create_backup(file_path)
            
            # Read the encrypted file in binary mode
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Get original filename by removing .vault extension
            decrypted_file = file_path.with_suffix('').with_suffix('')
            
            # Write the decrypted data in binary mode
            with open(decrypted_file, 'wb') as f:
                f.write(decrypted_data)
            
            # Remove encrypted file
            os.remove(file_path)
            logging.info(f"Decrypted: {file_path}")
            
        except Exception as e:
            logging.error(f"Decryption failed for {file_path}: {e}")
            raise



    
def display_banner():
    """Display the application banner."""
    return '''
  __      __             _______  ______  _______   ______
 /  \\    /  \\           /  __   \\/  __  \\/  __   \\ /  __  \\
 \\   \\/\\/   /  VaultSecure  |  |_/  /|  |_/  /|  |_/  /|  |  
  \\        /    Protect |   __/  |   __/ |   __/ |   __/   
   \\__/\\  /   Your Data |  |     |  |    |  |    |  |      
        \\/   Securely   |__|     |__|    |__|    |__|      

 <1> Generate a new encryption key
 <2> Decrypt a folder
 <3> Encrypt a folder
 <4> Configure settings
 <5> View recent directories
 <6> Manage backups
 <7> Exit VaultSecure
'''

def main():
    # Create base directory structure
    base_dir = r"C:\Users\Gaurika\Desktop\pythoncodes\vaultsecure"
    os.makedirs(base_dir, exist_ok=True)
    
    vault = VaultSecure()
    
    while True:
        os.system('cls')  # Using 'cls' for Windows
        print(display_banner())
        
        try:
            option = int(input(' Choose an option: '))
            print('\n')
            
            if option == 1:
                default_key_dir = os.path.join(base_dir, "keys")
                key_dir = input(f' Directory to save key (press Enter for {default_key_dir}): ').strip()
                if not key_dir:
                    key_dir = default_key_dir
                
                key_name = input(' Key name (e.g., "my_secret_key"): ').strip()
                use_password = input(' Protect key with password? (y/n): ').lower() == 'y'
                password = getpass.getpass(' Enter password: ') if use_password else None
                
                if vault.generate_key(key_dir, key_name, password):
                    input('\n[Success] Key generated! Press <ENTER> to return...')
            
            elif option in [2, 3]:
                key_path = input(' Path to the key file: ').strip()
                dir_path = input(f' Directory to {"decrypt" if option == 2 else "encrypt"}: ').strip()
                use_password = input(' Is the key password-protected? (y/n): ').lower() == 'y'
                password = getpass.getpass(' Enter password: ') if use_password else None
                
                if vault.process_files(key_path, dir_path, option == 3, password):
                    input('\n[Success] Operation completed! Press <ENTER> to return...')
            
            elif option == 4:
                print(" Settings:")
                print(" 1. Toggle backups (currently", "enabled" if vault.config["backup_enabled"] else "disabled", ")")
                print(" 2. Change backup location")
                print(" 3. Change max recent directories")
                
                setting = int(input("\n Choose setting to modify: "))
                if setting == 1:
                    vault.config["backup_enabled"] = not vault.config["backup_enabled"]
                elif setting == 2:
                    vault.config["backup_location"] = input(" New backup location: ").strip()
                elif setting == 3:
                    vault.config["max_recent_dirs"] = int(input(" Max number of recent directories: "))
                vault.save_config()
                input('\n[Success] Settings updated! Press <ENTER> to return...')
            
            elif option == 5:
                print(" Recent Directories:")
                if vault.config["recent_directories"]:
                    for i, directory in enumerate(vault.config["recent_directories"], 1):
                        print(f" {i}. {directory}")
                else:
                    print(" No recent directories found.")
                input("\nPress <ENTER> to return...")
            
            elif option == 6:
                backup_dir = Path(vault.config["backup_location"])
                if backup_dir.exists():
                    print(" Backup Management:")
                    print(" 1. List backups")
                    print(" 2. Clear old backups")
                    backup_option = int(input("\n Choose option: "))
                    
                    if backup_option == 1:
                        backups = list(backup_dir.glob("*.backup"))
                        if backups:
                            for backup in backups:
                                print(f" - {backup.name}")
                        else:
                            print(" No backups found.")
                    elif backup_option == 2:
                        days = int(input(" Delete backups older than (days): "))
                        cutoff = datetime.now().timestamp() - (days * 86400)
                        deleted = 0
                        for backup in backup_dir.glob("*.backup"):
                            if backup.stat().st_mtime < cutoff:
                                backup.unlink()
                                deleted += 1
                        print(f"\n[Success] Deleted {deleted} old backups.")
                    input("\nPress <ENTER> to return...")
                else:
                    input("\n[Error] Backup directory not found. Press <ENTER> to return...")
            
            elif option == 7:
                break
            
            else:
                print(' [Error] Invalid option. Please try again.')
                input('\nPress <ENTER> to continue...')
                
        except KeyboardInterrupt:
            print('\n [Info] Exiting VaultSecure...')
            break
        except ValueError as e:
            print(f'\n [Error] Invalid input: {e}')
            input('\nPress <ENTER> to continue...')
        except Exception as e:
            logging.error(f"Error: {e}")
            print(f'\n [Error] An unexpected error occurred: {e}')
            input('\nPress <ENTER> to continue...')
    
    sys.exit('\n\n[Info] Thank you for using VaultSecure! Stay safe.\n')


if __name__ == "__main__":
    main()