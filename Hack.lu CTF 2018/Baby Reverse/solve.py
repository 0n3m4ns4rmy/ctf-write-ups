encrypted = '\n\r\006\034\"8\030&6\017\071+\034YB,6\032,&\034\027-9WC\001\a+8\t\a\032\001\027\023\023\027-9\n\r\006F\\}'

encrypted = encrypted[::-1]
key = encrypted[:1]

for i in range(len(encrypted) - 1):
	key += chr(ord(key[i]) ^ ord(encrypted[i+1]))

key = key[::-1]

print key
