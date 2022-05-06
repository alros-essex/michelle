'''Michelle'''

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import os
import subprocess
from colorama import Fore

class Michelle():
    """my Shell"""

    def __init__(self) -> None:
        """initialize the commands"""
        self.commands = {
            # prints the help
            'help': Michelle.do_help,
            # changes directory
            'cd': Michelle.do_cd,
            # lists files in the current directory
            'LIST': Michelle.do_list,
            # sums two numbers
            'ADD': Michelle.do_add,
            # encrypts a file
            'ENCRYPT': Michelle.do_encrypt,
            # decrypts a file
            'DECRYPT': Michelle.do_decrypt,
            # quits
            'EXIT': None
        }

    def run(self) -> None:
        """Main loop"""
        while True:
            # gets the commandline
            line = input("$ ").strip()
            # skip if empty
            if not line.strip():
                continue
            # splits it in components
            parts = line.split(' ')
            # if it's not a known command...
            if not parts[0] in self.commands:
                try:
                    # ...pass it to the standard shell
                    subprocess.run(parts, check=True)
                except Exception as exception:
                    # prints errors
                    _print(exception, Fore.YELLOW)
                continue
            # EXIT is not a real command, it just breaks the loop
            if parts[0] == 'EXIT':
                break
            # if none of the above, it's a custom command
            self.commands[parts[0]](self, parts[0], parts[1:])

    def do_help(self, _a, _b):
        """executes the HELP command"""
        for command in self.commands:
            _print(command, Fore.CYAN)

    def do_cd(self, _, params):
        """executes the CD command"""
        path = ' '.join(params)
        try:
            os.chdir(os.path.abspath(path))
        except Exception:
            _print(f'cd: no such file or directory: {path}', Fore.YELLOW)

    def do_list(self, _a, _b):
        """executes the LIST command"""
        # prints sorted and colored
        for element in sorted(os.listdir()):
            _print(element, Fore.WHITE if os.path.isfile(element) else Fore.GREEN)

    def do_add(self, _, params):
        """add numbers passed as parameters"""
        total = 0
        try:
            # this is just a loop to sum numbers
            for element in params:
                total = total + int(element)
            _print(f'the sum is {total}', Fore.GREEN)
        except Exception as _:
            _print(f'invalid number: {element}', Fore.YELLOW)

    def do_encrypt(self, _, params):
        """encrypts a file"""
        # gets the password
        input_password = getpass.getpass('password: ')
        # some magic to encode the password, add salt and create the context
        password = input_password.encode('utf-8')
        salt = _get_salt()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), # the algorithm 
                         length=32,
                         salt=salt,
                         iterations=390000) # increase iterations to make it stronger
        key = base64.urlsafe_b64encode(kdf.derive(password))
        fernet = Fernet(key)
        try:
            # actual encryption
            with open(params[0], 'rb') as input_file:
                # this reads the whole file, it's not suitable for large inputs
                data = input_file.read()
                # encrypts in memory, also not optimal
                encrypted_data = fernet.encrypt(data)
                # finally writes the output with .enc as a suffix
                with open(f'{params[0]}.enc', 'wb') as output_file:
                    output_file.write(encrypted_data)
        except Exception as exception:
            _print(exception, Fore.YELLOW)

    def do_decrypt(self, _, params):
        """decrypts a file"""
        # gets the password
        input_password = getpass.getpass('password: ')
        # same as for the encryption
        password = input_password.encode('utf-8')
        salt = _get_salt()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=salt,
                         iterations=390000)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        fernet = Fernet(key)
        try:
            with open(params[0], 'rb') as input_file:
                # this reads the whole file, it's not suitable for large inputs
                data = input_file.read()
                # dencrypts in memory, also not optimal    
                decrypted_data = fernet.decrypt(data)
                # finally writes the output with .dec as a suffix
                with open('.'.join(params[0].split('.')[:-1]) + '.dec', 'wb') as output_file:
                    output_file.write(decrypted_data)
        except Exception as exception:
            _print(exception, Fore.YELLOW)
        

def _print(line:str, color_fg):
    """utility method to add colors"""
    print(f'{color_fg}{line}{Fore.RESET}')

def _get_salt():
    """generates a salt for the encryption"""
    salt_file_name = '.salt'
    if not os.path.exists(salt_file_name):
        # save the salt locally
        with open(salt_file_name, 'wb') as salt_file:
            salt_file.write(os.urandom(16))
    # return current salt: don't forget to backup it!
    with open(salt_file_name, 'rb') as salt_file:
        return salt_file.read()