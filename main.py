#!/usr/bin/env python3
import hashlib
import aes.main as aes
from password_generator import generate_password
import sys
import pyperclip
import json
from getpass import getpass

class App:
    def __init__(self, password):
        self.password = password
        length = 16
        tag = ""
        new_password = ""
        debug = False
        new = False
        existing = False

    def login(self):
        try:
            data = json.load(open('data.json', 'r'))
        except FileNotFoundError:
            data = ""
            password = getpass("Create password: ")
            data = hashlib.sha256(password.encode()).hexdigest()
            print("Password created")
            json.dump(data, open('data.json', 'w'))
            print("Successfully logged in")
            return password
        password = getpass('Enter your password: ')
        hash = hashlib.sha256(password.encode()).hexdigest()
        if hash != data:
            print('Wrong password!')
            sys.exit(1)
        print("Successfully logged in")
        return password


    def new_password(self):
        print("Generating new password")
        password = generate_password(self.length, self.no_symbols)
        print("Password generated")
        if self.debug:
            print(password)
        encrypted_password = aes.encrypt(self.password, self.user_password)
        self.passwords[tag] = encrypted_password
        pyperclip.copy(password)
        print("Password copied to clipboard")
        json.dump(passwords, open('passwords.json', 'w'), indent=4)


    def main(self):
        try:
            self.passwords = json.load(open('passwords.json'))
        except:
            self.passwords = {}
            print("No passwords found. Creating new file.")
        args = sys.argv[1:]
        no_symbols = False
        for i, arg in enumerate(args):
            if arg == "-l":
                length = int(args[i+1])
            elif arg == "-n":
                new = True
            elif arg == "-e":
                existing = True
            elif arg == "-ns" or arg == "--no-symbols":
                no_symbols = True
            elif arg == "-p" or arg == "-d":
                debug = True
            elif arg[0] != "-":
                if tag:
                    if new_password:
                        print("too much arguments")
                        return
                    new_password = arg
                else:
                    tag = arg
        if tag:
            user_password = login()
            if new:
            if existing:
                new_password = getpass("Enter new password: ")
                encrypted_password = aes.encrypt(new_password, user_password)
                passwords[tag] = encrypted_password
                json.dump(passwords, open('passwords.json', 'w'), indent=4)
            if not new and not existing:
                if new_password:
                    print("Encrypting password...")
                    encrypted_password = aes.encrypt(new_password, user_password)
                    print("Password encrypted")
                    passwords[tag] = encrypted_password
                    pyperclip.copy(new_password)
                    print("Password copied to clipboard")
                    json.dump(passwords, open('passwords.json', 'w'), indent=4)
                else:
                    encrypted_password = passwords[tag]
                    print("Decrypting password...")
                    password = aes.decrypt(encrypted_password, user_password)
                    pyperclip.copy(password)
                    print("Password copied to clipboard")
                    if debug:
                        print(password)
        else:
            for tag in passwords:
                print(tag)


if __name__ == '__main__':
    pm = PasswordManager()
    pm.main()
