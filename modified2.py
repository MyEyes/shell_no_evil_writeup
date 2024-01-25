from pwn import *
context.log_level = "error" #get rid of annoying connect disconnect prints
kBuiltinShellcode = b"\x00\x00\x11\x42\x01\x00\xfa\x0b"

def attempt(shellcode):
    with remote("localhost", 5000) as r:
        r.recvuntil(b"(0 to use the builtin): ")
        r.sendline(f"{len(shellcode)}".encode())
        r.recvuntil(b"bytes of shellcode: ")
        r.send(shellcode)
        return r.clean(timeout=0.5)

if __name__ == "__main__":
    for i in range(256):
        print(hex(i))
        sc = kBuiltinShellcode[0:3]+bytes([i])+kBuiltinShellcode[4:8]
        print(attempt(sc).decode())