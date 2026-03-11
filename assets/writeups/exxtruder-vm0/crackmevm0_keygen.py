import random
import string

def gen_serial(name: str) -> str:

    i = 0
    serial = ""
    while i < 8:
        if i == 0:
            serial += name[6]
        elif i == 2:
            serial += name[3]
        elif i == 3:
            serial += name[9]
        elif i == 5:
            serial += name[2]
        elif i == 7:
            serial += name[1]
        else:
            serial += random.choice(string.ascii_uppercase)
        i += 1
    return serial


if __name__ == "__main__":
    name = input("name (10 letters): ")
    if len(name) < 10:
        name = name + "Z"*(10-len(name))
    elif len(name) > 10:
        name = name[:10]
    name = name.upper()
    serial = gen_serial(name)
    print(f"name: {name}")
    print(f"serial: {serial}")
    

