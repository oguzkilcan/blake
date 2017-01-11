package blake

var u256 = []uint32{
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
}

var u512 = []uint64{
	0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
	0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
	0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
	0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
}

var sigma = []int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
	11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
	7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
	9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
	2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
	12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
	13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
	6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
	10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
}

func block256(d *digest256, p []uint8) {
	var h [8]uint32
	for i := 0; i < 8; i++ {
		h[i] = d.h[i]
	}

	for len(p) >= BlockSize256 {
		var v [16]uint32
		for i := 0; i < 4; i++ {
			v[i], v[i+4] = h[i], h[i+4]
			v[i+8], v[i+12] = d.s[i]^u256[i], u256[i+4]
		}

		d.t += 512
		if !d.nullt {
			v[12] ^= uint32(d.t)
			v[13] ^= uint32(d.t)
			v[14] ^= uint32(d.t >> 32)
			v[15] ^= uint32(d.t >> 32)
		}

		var m [16]uint32
		for i, j := 0, 0; i < 16; i, j = i+1, j+4 {
			m[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		for i := 0; i < 14; i++ {
			for j := 0; j < 4; j++ {
				v[j], v[j+4], v[j+8], v[j+12] = g256(v[j], v[j+4], v[j+8], v[j+12], m, i, j)
			}
			for j := 0; j < 4; j++ {
				v[j], v[((j+1)%4)+4], v[((j+2)%4)+8], v[((j+3)%4)+12] = g256(v[j], v[((j+1)%4)+4], v[((j+2)%4)+8], v[((j+3)%4)+12], m, i, j+4)
			}
		}

		for i := 0; i < 8; i++ {
			h[i] ^= d.s[i%4] ^ v[i] ^ v[i+8]
		}
		p = p[BlockSize256:]
	}

	for i := 0; i < 8; i++ {
		d.h[i] = h[i]
	}
}

func block512(d *digest512, p []uint8) {
	var h [8]uint64
	for i := 0; i < 8; i++ {
		h[i] = d.h[i]
	}

	for len(p) >= BlockSize512 {
		var v [16]uint64
		for i := 0; i < 4; i++ {
			v[i], v[i+4] = h[i], h[i+4]
			v[i+8], v[i+12] = d.s[i]^u512[i], uint64(u512[i+4])
		}

		d.t += 1024
		if !d.nullt {
			v[12] ^= d.t
			v[13] ^= d.t
			v[14] ^= 0
			v[15] ^= 0
		}

		var m [16]uint64
		for i, j := 0, 0; i < 16; i, j = i+1, j+8 {
			m[i] = uint64(p[j])<<56 | uint64(p[j+1])<<48 | uint64(p[j+2])<<40 | uint64(p[j+3])<<32 | uint64(p[j+4])<<24 | uint64(p[j+5])<<16 | uint64(p[j+6])<<8 | uint64(p[j+7])
		}

		for i := 0; i < 16; i++ {
			for j := 0; j < 4; j++ {
				v[j], v[j+4], v[j+8], v[j+12] = g512(v[j], v[j+4], v[j+8], v[j+12], m, i, j)
			}
			for j := 0; j < 4; j++ {
				v[j], v[((j+1)%4)+4], v[((j+2)%4)+8], v[((j+3)%4)+12] = g512(v[j], v[((j+1)%4)+4], v[((j+2)%4)+8], v[((j+3)%4)+12], m, i, j+4)
			}
		}

		for i := 0; i < 8; i++ {
			h[i] ^= d.s[i%4] ^ v[i] ^ v[i+8]
		}
		p = p[BlockSize512:]
	}

	for i := 0; i < 8; i++ {
		d.h[i] = h[i]
	}
}

func g256(a uint32, b uint32, c uint32, d uint32, m [16]uint32, i int, j int) (uint32, uint32, uint32, uint32) {
	a += (m[sigma[(i%10)*16+(2*j)]] ^ u256[sigma[(i%10)*16+(2*j+1)]])
	a += b
	d ^= a
	d = d<<(32-16) | d>>16
	c += d
	b ^= c
	b = b<<(32-12) | b>>12
	a += (m[sigma[(i%10)*16+(2*j+1)]] ^ u256[sigma[(i%10)*16+(2*j)]])
	a += b
	d ^= a
	d = d<<(32-8) | d>>8
	c += d
	b ^= c
	b = b<<(32-7) | b>>7
	return a, b, c, d
}

func g512(a uint64, b uint64, c uint64, d uint64, m [16]uint64, i int, j int) (uint64, uint64, uint64, uint64) {
	a += (m[sigma[(i%10)*16+(2*j)]] ^ u512[sigma[(i%10)*16+(2*j+1)]])
	a += b
	d ^= a
	d = d<<(64-32) | d>>32
	c += d
	b ^= c
	b = b<<(64-25) | b>>25
	a += (m[sigma[(i%10)*16+(2*j+1)]] ^ u512[sigma[(i%10)*16+(2*j)]])
	a += b
	d ^= a
	d = d<<(64-16) | d>>16
	c += d
	b ^= c
	b = b<<(64-11) | b>>11
	return a, b, c, d
}
