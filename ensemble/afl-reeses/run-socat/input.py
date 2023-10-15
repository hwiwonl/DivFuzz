import struct
import sys

data = open(sys.argv[1], 'rb').read()
data_len = struct.pack('I', len(data))
sys.stdout.write(data_len + data)
