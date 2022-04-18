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
    '''my Shell'''

    def __init__(self) -> None:
        '''initialize the commands'''
        self.commands = {
            'help': Michelle.do_help,
            'cd': Michelle.do_cd,
            'LIST': Michelle.do_list,
            'ADD': Michelle.do_add,
            'ENCRYPT': Michelle.do_encrypt,
            'DECRYPT': Michelle.do_decrypt,
            'EXIT': None
        }

    def run(self) -> None:
        '''Main loop'''
        while True:
            line = input("$ ").strip()
            if not line.strip():
                continue
            parts = line.split(' ')
            if not parts[0] in self.commands:
                try:
                    subprocess.run(parts, check=True)
                except Exception as exception:
                    _print(exception, Fore.YELLOW)
                continue
            if parts[0] == 'EXIT':
                break
            self.commands[parts[0]](self, parts[0], parts[1:])

    def do_help(self, _a, _b):
        '''executes the HELP command'''
        for command in self.commands:
            _print(command, Fore.CYAN)

    def do_cd(self, _, params):
        '''executes the CD command'''
        path = ' '.join(params)
        try:
            os.chdir(os.path.abspath(path))
        except Exception:
            _print(f'cd: no such file or directory: {path}', Fore.YELLOW)

    def do_list(self, _a, _b):
        '''executes the LIST command'''
        for element in sorted(os.listdir()):
            _print(element, Fore.WHITE if os.path.isfile(element) else Fore.GREEN)

    def do_add(self, _, params):
        '''add numbers passed as parameters'''
        total = 0
        try:
            for element in params:
                total = total + int(element)
            _print(f'the sum is {total}', Fore.GREEN)
        except Exception as _:
            _print(f'invalid number: {element}', Fore.YELLOW)

    def do_encrypt(self, _, params):
        input_password = getpass.getpass('password: ')
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
                data = input_file.read()
                encrypted_data = fernet.encrypt(data)
                with open(f'{params[0]}.enc', 'wb') as output_file:
                    output_file.write(encrypted_data)
        except Exception as exception:
            _print(exception, Fore.YELLOW)

    def do_decrypt(self, _, params):
        input_password = getpass.getpass('password: ')
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
                data = input_file.read()
                decrypted_data = fernet.decrypt(data)
                with open('.'.join(params[0].split('.')[:-1]) + '.dec', 'wb') as output_file:
                    output_file.write(decrypted_data)
        except Exception as exception:
            _print(exception, Fore.YELLOW)
        

def _print(line:str, color_fg):
    '''utility method to add colors'''
    print(f'{color_fg}{line}{Fore.RESET}')

def _get_salt():
    salt_file_name = '.salt'
    if not os.path.exists(salt_file_name):
        with open(salt_file_name, 'wb') as salt_file:
            salt_file.write(os.urandom(16))
    with open(salt_file_name, 'rb') as salt_file:
        return salt_file.read()