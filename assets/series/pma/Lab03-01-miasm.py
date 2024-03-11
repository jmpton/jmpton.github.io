import argparse
import hashlib
import json
import os
import pefile
import struct
import sys

from miasm.core.asmblock import AsmBlockBad
from miasm.core.interval import interval
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import ExprInt, ExprLoc, ExprId, ExprMem
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE


def locate_hidden_data(raw):
    """
    Look for basic blocks ending with a "CALL" insn.
    Then check if the destination bbl start with a "POP" or a "CALL" insn.
    In both cases the 1st call puts a pointer on the stack, which is either
    (i) popped in a register or (ii) used as an argument by the 2nd call.
    The disassembly logic (double while loop, use of interval for fn discovery)
    comes from miasm example code, see:
    https://github.com/cea-sec/miasm/blob/master/example/disasm/full.py
    TODO: the code fails, however, if the dest starts with a push.
    An other way to think about this is check the fallthrough,
    and see if it contains ascii and / or can be disassembled.
    :param raw: sample to analyze (bytes object)
    :return: [(addr_data_start, addr_data_end), ...]
    """

    candidates = []

    # Load PE
    pe = Container.from_string(raw)
    # Abstract machine arch
    machine = Machine(pe.arch)
    # instanciate a disassembler
    mdis = machine.dis_engine(pe.bin_stream, loc_db=pe.loc_db, follow_call=True)

    all_regs = machine.mn.regs.all_regs_ids_byname

    todo = []
    done = set()
    done_interval = interval()
    use_intervals = True

    # Use address 0x400400 (.data) as alternate entrypoint,
    # because code at OEP is just a "mov eax, 0x400400; call eax"
    entrypoint = 0x400400
    todo.append(entrypoint)

    while todo:
        while todo:
            offset = todo.pop()
            if offset in done:
                continue
            done.add(offset)

            # Instanciate an AsmCFG() instance
            asmcfg = mdis.dis_multiblock(offset)

            # iterate through AsmBlock()
            for block in asmcfg.blocks:
                # Avoid bad blocks
                if not isinstance(block, AsmBlockBad):
                    # if asmcfg.loc_db.get_location_offset(block.loc_key) == 0x4007b4:
                        # print(hex(offset))

                    # The black magic of intervals:
                    # iterate over all lines (each line representing an instruction)
                    # of a basic block, taking into account the size of instructions.
                    # When at the last line, adding its size allows to reach an eventual
                    # new block next to it, that otherwise couldn't have been reached
                    # (e.g: indirect call).
                    for line in block.lines:
                        done_interval += interval([(line.offset, line.offset+line.l)])

                    # Retrieve the call (if any) at the end of the bbl
                    insn = block.get_subcall_instr()
                    if insn:
                        # Retrieve the destination of the call.
                        # We're interested in dest of the form "loc_key_xx",
                        # because calling somewhere in the code will push an
                        # address on the stack that can be address of data.
                        arg = insn.args[0]
                        if isinstance(arg, ExprLoc):
                            # Retrieve dest and fallthrough;
                            # if only 1 element, it's a call $+5 and we
                            # don't want it.
                            asm_constraints = block.bto
                            if len(asm_constraints) == 1:
                                continue
                            dest_loc = None
                            fallthrough_loc = None
                            # print(hex(asmcfg.loc_db.get_location_offset(block.loc_key)))
                            for constr in asm_constraints:
                                if constr.c_t == "c_to":
                                    dest_loc = constr.loc_key
                                elif constr.c_t == "c_next":
                                    fallthrough_loc = constr.loc_key
                                else:
                                    print("[-] Missing loc")
                                    print(block)
                                    break

                            # Once we have the dest and fallthrough branches,
                            # we inspect the destination block:
                            # if it starts with call or pop, it's a win :)
                            dest_block = asmcfg.loc_key_to_block(dest_loc)
                            if not isinstance(dest_block, AsmBlockBad):
                                dest_insn = dest_block.lines[0]
                                if dest_insn.name == "CALL" :
                                    data_start = asmcfg.loc_db.get_location_offset(fallthrough_loc)
                                    data_end = asmcfg.loc_db.get_location_offset(dest_loc)
                                    candidates.append((data_start, data_end))
                                if dest_insn.name == "POP" and isinstance (dest_insn.args[0], ExprId):
                                    data_start = asmcfg.loc_db.get_location_offset(fallthrough_loc)
                                    data_end = asmcfg.loc_db.get_location_offset(dest_loc)
                                    candidates.append((data_start, data_end))
                                # TODO: handle cases where 2 arguments are put on stack,
                                # the 1st with a call and the second with a push (e;g.: 0x4018e5)

        if use_intervals:
            for start, end in done_interval.intervals:
                if end in done:
                    continue

                todo.append(end)

    #print(done_interval)
    return candidates


def get_hidden_data(path, info_hidden_data):
    """
    Use pefile library to retrieve raw data from their location
    :param path: path of the sample
    :param info_hidden_data: From locate_hidden_data()
    :return: [(addr_data_start, data),...]
    """

    hidden_data = []

    pe = pefile.PE(path)
    imagebase = pe.OPTIONAL_HEADER.ImageBase

    for e in info_hidden_data:
        rva_start = e[0] - imagebase
        rva_end = e[1] - imagebase
        data = pe.get_data(rva_start, (rva_end-rva_start))
        hidden_data.append((e[0], data))

    return hidden_data


def jitter_callback_start(sb):
    print("[+] Hash computation starts")
    return True

def jitter_callback_end(sb):
    #print("[!] End of emulation.")
    #print("Target hash: {}. Result: {}".format(hex(sb.cpu.EDX), hex(sb.cpu.EAX)))
    result = sb.cpu.EAX
    sb.run = False
    sb.pc = 0
    return result

def jit_snippet(raw, hashes_to_find, api_list):

    start = 0x400aef
    end = 0x400b29
    name2hash = {}

    for file in os.listdir(api_list):

        file_path = os.path.join(api_list, file)
        f = open(file_path, "r")
        api_names = f.readlines()

        print("[*] Parsing file {} ({} names)".format(file, len(api_names)))

        for l in api_names:

            l = l.split('\n')[0]
            str_to_hash = l.encode("utf8")
            str_to_hash += b'\x00' #

            sb = Machine("x86_32").jitter()
            sb.init_stack()
            # print(sb.stack_base)

            # Dummy push for stack align (pop edx at 0x400b26);
            # in original code, it's the hash to find.
            sb.push_uint32_t(0x00c0ffee)

            # sb.add_breakpoint(start, jitter_callback_start)
            sb.add_breakpoint(end, jitter_callback_end)

            sb.vm.add_memory_page(0x400000, PAGE_READ | PAGE_WRITE, raw) # code
            #sb.vm.add_memory_page(0x500000, PAGE_READ | PAGE_WRITE, raw) # data
            sb.vm.add_memory_page(0x500000, PAGE_READ | PAGE_WRITE, str_to_hash) # data

            # DEBUG
            # str_to_hash = "LoadLibraryA".encode("utf8")
            # str_to_hash += b'\x00'
            # DEBUG

            #sb.vm.set_mem(0x500000, str_to_hash)

            sb.cpu.EAX = 0
            sb.cpu.EBX = 0
            sb.cpu.ECX = 0xffffffff
            sb.cpu.EDX = 0xffffffff
            sb.cpu.EDI = len(str_to_hash)
            sb.cpu.ESI = 0x500000

            result = sb.run(addr=start)

            # DEBUG
            # hashes_to_find = [0, 0x4134d1ad]
            # DEBUG

            if result in hashes_to_find:
                api_name = str_to_hash[:-1].decode("utf8")
                name2hash[api_name] = result
                print("[+] Hash match {}:{}".format(hex(result), api_name))

        f.close()

    r = json.dumps(name2hash)

    return r

def main(path, raw):
    """
    :param path: path of the sample
    :param raw: sample to analyze (bytes object)
    :return:
    """

    # Search for calls used to push data on stack
    info_hidden_data = locate_hidden_data(raw)
    hidden_data = get_hidden_data(path, info_hidden_data)
    if len(hidden_data) > 0:
        print("======================")
        print("[+] Found hidden data:")
        print("======================")
        for e in hidden_data:
            print(hex(e[0]), repr(e[1]))

    # Retrieve API hashes from struct at 0x40129b;
    # Struct is dw, w, w; we're interested in dw, thus i+=8
    raw_hashes = b''
    api_hashes = []
    addr_table_hashes = 0x40129b
    for e in hidden_data:
        if e[0] == addr_table_hashes:
            i = 0
            raw_hashes = e[1]
            if len(raw_hashes) >= 4:
                while True:
                    if raw_hashes[i:i+4] == b'\x00\x00\x00\x00':
                        break
                    hash = struct.unpack("<I", raw_hashes[i:i+4])[0]
                    api_hashes.append(hash)
                    i += 8
            break

    # More hashes, retrieved manually from calls to ImportByHash() function
    more_hashes = [
        0x4134D1AD,
        0x04DCF392,
        0x3921BF03,
        0x7E04376B,
        0xE6E5030E,
        0x87D52C94,
        0xA10A30B6,
        0xFE248274,
        0x593AE7CE
    ]
    api_hashes += more_hashes

    # Winsock2 hashes
    ws2_hashes = [
        0x8EB460E1,
        0x7C2941D1,
        0x65ECBB1E,
        0xEAED580C,
        0x5F7E2D81,
        0x377022BA,
        0x7A3CE88A,
        0x1CC6CDC5,
        0x492DDFD7,
        0xBBA4D88F
    ]

    api_hashes += ws2_hashes

    # Dict attack CRC32 of API names.
    # Set flag to True to retreive hashes and dump results to json file
    # Directory "dll_list" contains text files containing API names:
    #   head ../dll_list/sysdlls.kernel32.txt
    #   ActivateActCtx
    #   AddAtomA
    #   AddAtomW
    #   ...
    # "path" is work directory
    # "raw" is the binary sample (byte object)
    dict_attack = True
    if dict_attack:
        api_names = os.path.join(os.path.dirname(path), "venv/dll_list") # dirty
        if os.path.exists(api_names):
            r = jit_snippet(raw, hashes_to_find=api_hashes, api_list=api_names)
            print(r)
            with open("api2hash.json", "w") as f:
                f.write(r)

    # Pretty print hash2api
    with open("api2hash.json", "r") as f:
        data = f.read()
    j = json.loads(data)

    for api_name, crc32 in j.items():
        print("{}\t{}".format(hex(crc32), api_name))

    return True

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Lab03-01")
    parser.add_argument("sample", type=str, help="Path of the sample")

    args = parser.parse_args()

    if os.path.exists(args.sample):
        with open(args.sample, "rb") as f:
            raw = f.read()
        if hashlib.md5(raw).hexdigest() != "d537acb8f56a1ce206bc35cf8ff959c0":
            print("[-] File hash doesn't match.")
            sys.exit(0)

        status = main(args.sample, raw)

        sys.exit(0)

    print("[-] File not found.")
    sys.exit(0)

