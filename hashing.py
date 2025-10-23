from struct import pack, unpack

#  helper functions
def _rotl32(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def _rotr32(x, n): return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# MD5
# Initial state
_MD5_INIT = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

# Per-round left-rotate amounts
_MD5_S = [
    7,12,17,22,  7,12,17,22,  7,12,17,22,  7,12,17,22,
    5, 9,14,20,  5, 9,14,20,  5, 9,14,20,  5, 9,14,20,
    4,11,16,23,  4,11,16,23,  4,11,16,23,  4,11,16,23,
    6,10,15,21,  6,10,15,21,  6,10,15,21,  6,10,15,21
]

# K[i] constants 
_MD5_K = [
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
]

def _md5_compress(state, block):
    a,b,c,d = state
    X = list(unpack("<16I", block))
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d); g = i
        elif i < 32:
            f = (d & b) | (~d & c); g = (5*i + 1) & 15
        elif i < 48:
            f = b ^ c ^ d;          g = (3*i + 5) & 15
        else:
            f = c ^ (b | ~d);       g = (7*i) & 15
        f = (f + a + _MD5_K[i] + X[g]) & 0xFFFFFFFF
        a, d, c, b = d, c, b, (b + _rotl32(f, _MD5_S[i])) & 0xFFFFFFFF
    state[0] = (state[0] + a) & 0xFFFFFFFF
    state[1] = (state[1] + b) & 0xFFFFFFFF
    state[2] = (state[2] + c) & 0xFFFFFFFF
    state[3] = (state[3] + d) & 0xFFFFFFFF

def md5_hex(path):
    s = _MD5_INIT[:]
    total = 0; tail = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk: break
            total += len(chunk)
            chunk = tail + chunk
            n = (len(chunk)//64)*64
            for i in range(0, n, 64): _md5_compress(s, chunk[i:i+64])
            tail = chunk[n:]
    bitlen = (total*8) & 0xFFFFFFFFFFFFFFFF
    pad = b"\x80" + b"\x00"*(((56 - (len(tail)+1)) % 64)) + pack("<Q", bitlen)
    final = tail + pad
    for i in range(0, len(final), 64): _md5_compress(s, final[i:i+64])
    return "".join(f"{b:02x}" for b in pack("<4I", *s))

# SHA-1 
_SHA1_INIT = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]

def _sha1_compress(h, block):
    w = list(unpack(">16I", block)) + [0]*64
    for t in range(16, 80):
        w[t] = _rotl32(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1)
    a,b,c,d,e = h
    for t in range(80):
        if   t < 20: f=(b & c) | ((~b) & d); k=0x5A827999
        elif t < 40: f=b ^ c ^ d;            k=0x6ED9EBA1
        elif t < 60: f=(b & c) | (b & d) | (c & d); k=0x8F1BBCDC
        else:        f=b ^ c ^ d;            k=0xCA62C1D6
        temp = (_rotl32(a,5) + f + e + k + w[t]) & 0xFFFFFFFF
        a,b,c,d,e = temp, a, _rotl32(b,30), c, d
    h[0]=(h[0]+a)&0xFFFFFFFF; h[1]=(h[1]+b)&0xFFFFFFFF
    h[2]=(h[2]+c)&0xFFFFFFFF; h[3]=(h[3]+d)&0xFFFFFFFF
    h[4]=(h[4]+e)&0xFFFFFFFF

def sha1_hex(path):
    h = _SHA1_INIT[:]
    total=0; tail=b""
    with open(path,"rb") as f:
        while True:
            chunk=f.read(8192)
            if not chunk: break
            total+=len(chunk); chunk=tail+chunk
            n=(len(chunk)//64)*64
            for i in range(0,n,64): _sha1_compress(h,chunk[i:i+64])
            tail=chunk[n:]
    bitlen=(total*8)&0xFFFFFFFFFFFFFFFF
    pad=b"\x80"+b"\x00"*(((56-(len(tail)+1))%64))+pack(">Q",bitlen)
    final=tail+pad
    for i in range(0,len(final),64): _sha1_compress(h,final[i:i+64])
    return "".join(f"{x:08x}" for x in h)

#  SHA-256 
# Initial hash values H0..H7 
_H256_INIT = [
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
]

# Round constants K[64] 
_K256 = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]

def _sha256_compress(h, block):
    w = list(unpack(">16I", block)) + [0]*48
    for t in range(16,64):
        s0 = _rotr32(w[t-15],7) ^ _rotr32(w[t-15],18) ^ (w[t-15] >> 3)
        s1 = _rotr32(w[t-2],17) ^ _rotr32(w[t-2],19) ^ (w[t-2] >> 10)
        w[t] = (w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFF
    a,b,c,d,e,f,g,hv = h
    for t in range(64):
        S1 = _rotr32(e,6) ^ _rotr32(e,11) ^ _rotr32(e,25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hv + S1 + ch + _K256[t] + w[t]) & 0xFFFFFFFF
        S0 = _rotr32(a,2) ^ _rotr32(a,13) ^ _rotr32(a,22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        hv,g,f,e,d,c,b,a = g,f,e,(d+temp1)&0xFFFFFFFF,c,b,a,(temp1+temp2)&0xFFFFFFFF
    h[0]=(h[0]+a)&0xFFFFFFFF; h[1]=(h[1]+b)&0xFFFFFFFF
    h[2]=(h[2]+c)&0xFFFFFFFF; h[3]=(h[3]+d)&0xFFFFFFFF
    h[4]=(h[4]+e)&0xFFFFFFFF; h[5]=(h[5]+f)&0xFFFFFFFF
    h[6]=(h[6]+g)&0xFFFFFFFF; h[7]=(h[7]+hv)&0xFFFFFFFF

def sha256_hex(path):
    h = _H256_INIT[:]
    total=0; tail=b""
    with open(path,"rb") as f:
        while True:
            chunk=f.read(8192)
            if not chunk: break
            total+=len(chunk); chunk=tail+chunk
            n=(len(chunk)//64)*64
            for i in range(0,n,64): _sha256_compress(h,chunk[i:i+64])
            tail=chunk[n:]
    bitlen=(total*8)&0xFFFFFFFFFFFFFFFF
    pad=b"\x80"+b"\x00"*(((56-(len(tail)+1))%64))+pack(">Q",bitlen)
    final=tail+pad
    for i in range(0,len(final),64): _sha256_compress(h,final[i:i+64])
    return "".join(f"{x:08x}" for x in h)
