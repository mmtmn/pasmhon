#!/usr/bin/env python3
import sys, re, os, stat, subprocess

# base virtual addresses
BASE   = 0x400000
CODEVA = BASE + 0x80
DATAVA = BASE + 0x100

def build_print(msg):
    code = []
    code += [0x48,0xc7,0xc0,1,0,0,0]                     # mov rax,1
    code += [0x48,0xc7,0xc7,1,0,0,0]                     # mov rdi,1
    code += [0x48,0xbe] + list(DATAVA.to_bytes(8,'little'))  # mov rsi,msg
    code += [0x48,0xc7,0xc2] + list(len(msg).to_bytes(4,'little'))  # mov rdx,len
    code += [0x0f,0x05]                                  # syscall
    code += [0x48,0xc7,0xc0,60,0,0,0]                    # mov rax,60
    code += [0x48,0x31,0xff]                             # xor rdi,rdi
    code += [0x0f,0x05]                                  # syscall
    return bytes(code)

def elf64(code, data):
    eh = bytearray()
    eh += b"\x7fELF"
    eh += b"\x02"
    eh += b"\x01"
    eh += b"\x01"
    eh += b"\x00"*9
    eh += (2).to_bytes(2,'little')
    eh += (0x3e).to_bytes(2,'little')
    eh += (1).to_bytes(4,'little')
    eh += CODEVA.to_bytes(8,'little')
    eh += (64).to_bytes(8,'little')
    eh += (0).to_bytes(8,'little')
    eh += (0).to_bytes(4,'little')
    eh += (64).to_bytes(2,'little')
    eh += (56).to_bytes(2,'little')
    eh += (1).to_bytes(2,'little')
    eh += (0).to_bytes(2,'little')
    eh += (0).to_bytes(2,'little')
    eh += (0).to_bytes(2,'little')

    ph = bytearray()
    ph += (1).to_bytes(4,'little')
    ph += (5).to_bytes(4,'little')
    ph += (0).to_bytes(8,'little')
    ph += BASE.to_bytes(8,'little')
    ph += BASE.to_bytes(8,'little')
    fsize = 0x100 + len(data)
    ph += fsize.to_bytes(8,'little')
    ph += fsize.to_bytes(8,'little')
    ph += (0x1000).to_bytes(8,'little')

    while len(eh) + len(ph) < 0x80:
        ph += b"\x00"

    blob = bytearray()
    blob += eh
    blob += ph
    blob += code

    while len(blob) < 0x100:
        blob += b"\x00"

    blob += data
    return blob

def main():
    if len(sys.argv) != 2:
        print("usage: pathon main.pa")
        sys.exit(1)

    src = open(sys.argv[1]).read().strip()
    m = re.match(r'print\("(.+)"\)', src)
    if not m:
        print("only print supported")
        sys.exit(1)

    msg = (m.group(1) + "\n").encode()
    code = build_print(msg)
    binfile = elf64(code, msg)

    os.makedirs("build", exist_ok=True)
    out = "build/main"
    open(out,"wb").write(binfile)
    os.chmod(out, 0o755)

    proc = subprocess.run([out], capture_output=True, text=True)
    print(proc.stdout, end="")
    sys.exit(proc.returncode)

if __name__=="__main__":
    main()
