'''Michelle'''

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
                subprocess.run(parts)
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
            _print("cd: no such file or directory: {}".format(path), Fore.YELLOW)
    
    def do_list(self, _a, _b):
        '''executes the LIST command'''
        for element in sorted(os.listdir()):
            _print(element, Fore.WHITE if os.path.isfile(element) else Fore.GREEN)

    def do_add(self, _, params):
        '''add numbers passed as parameters'''
        sum = 0
        try:
            for element in params:
                sum = sum + int(element)
            _print("the sum is {}".format(sum), Fore.GREEN)
        except Exception as exception:
            _print("invalid number: {}".format(element), Fore.YELLOW)

def _print(line:str, color_fg):
    '''utility method to add colors'''
    print('{color_fg}{line}{reset_fg}'.format(line = line,color_fg = color_fg, reset_fg = Fore.RESET))