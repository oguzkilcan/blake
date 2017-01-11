// Package blake implements SHA-3 finalist BLAKE-224,
// BLAKE-256, BLAKE-384 and BLAKE-512 hash functions.
package blake

import (
	"hash"
)

const (
	// Size224 is the size, in bytes, of a BLAKE-224 checksum.
	Size224 = 28

	// Size256 is the size, in bytes, of a BLAKE-256 checksum.
	Size256 = 32

	// Size384 is the size, in bytes, of a BLAKE-384 checksum.
	Size384 = 48

	// Size512 is the size, in bytes, of a BLAKE-512 checksum.
	Size512 = 64

	// BlockSize256 is the block size, in bytes, of the BLAKE-224
	// and BLAKE-256 hash functions.
	BlockSize256 = 64

	// BlockSize512 is the block size, in bytes, of the BLAKE-384
	// and BLAKE-512 hash functions.
	BlockSize512 = 128
)

const (
	chunk256  = 64
	chunk512  = 128
	init0_224 = 0xc1059ed8
	init1_224 = 0x367cd507
	init2_224 = 0x3070dd17
	init3_224 = 0xf70e5939
	init4_224 = 0xffc00b31
	init5_224 = 0x68581511
	init6_224 = 0x64f98fa7
	init7_224 = 0xbefa4fa4
	init0_256 = 0x6a09e667
	init1_256 = 0xbb67ae85
	init2_256 = 0x3c6ef372
	init3_256 = 0xa54ff53a
	init4_256 = 0x510e527f
	init5_256 = 0x9b05688c
	init6_256 = 0x1f83d9ab
	init7_256 = 0x5be0cd19
	init0_384 = 0xcbbb9d5dc1059ed8
	init1_384 = 0x629a292a367cd507
	init2_384 = 0x9159015a3070dd17
	init3_384 = 0x152fecd8f70e5939
	init4_384 = 0x67332667ffc00b31
	init5_384 = 0x8eb44a8768581511
	init6_384 = 0xdb0c2e0d64f98fa7
	init7_384 = 0x47b5481dbefa4fa4
	init0_512 = 0x6a09e667f3bcc908
	init1_512 = 0xbb67ae8584caa73b
	init2_512 = 0x3c6ef372fe94f82b
	init3_512 = 0xa54ff53a5f1d36f1
	init4_512 = 0x510e527fade682d1
	init5_512 = 0x9b05688c2b3e6c1f
	init6_512 = 0x1f83d9abfb41bd6b
	init7_512 = 0x5be0cd19137e2179
)

// digest256 represents the partial evaluation of a checksum
// for BLAKE-224 and BLAKE-256 functions.
type digest256 struct {
	h     [8]uint32
	s     [4]uint32
	t     uint64
	x     [chunk256]byte
	nx    int
	is224 bool
	nullt bool
}

// digest512 represents the partial evaluation of a checksum
// for BLAKE-384 and BLAKE-512 functions.
type digest512 struct {
	h     [8]uint64
	s     [4]uint64
	t     uint64
	x     [chunk512]byte
	nx    int
	is384 bool
	nullt bool
}

// New224 returns a new hash.Hash computing the BLAKE-224 checksum.
func New224() hash.Hash {
	d := new(digest256)
	d.is224 = true
	d.Reset()
	return d
}

// New256 returns a new hash.Hash computing the BLAKE-256 checksum.
func New256() hash.Hash {
	d := new(digest256)
	d.Reset()
	return d
}

// New384 returns a new hash.Hash computing the BLAKE-384 checksum.
func New384() hash.Hash {
	d := &digest512{is384: true}
	//d.is384 = true
	d.Reset()
	return d
}

// New512 returns a new hash.Hash computing the BLAKE-512 checksum.
func New512() hash.Hash {
	d := new(digest512)
	d.Reset()
	return d
}

// New224withSalt returns a new hash.Hash computing the BLAKE-224
// checksum but initializes with given 16-byte salt value.
func New224withSalt(salt []byte) hash.Hash {
	d := new(digest256)
	d.is224 = true
	d.setSalt(salt)
	d.Reset()
	return d
}

// New256withSalt returns a new hash.Hash computing the BLAKE-256
// checksum but initializes with given 16-byte salt value.
func New256withSalt(salt []byte) hash.Hash {
	d := new(digest256)
	d.setSalt(salt)
	d.Reset()
	return d
}

// New384withSalt returns a new hash.Hash computing the BLAKE-384
// checksum but initializes with given 32-byte salt value.
func New384withSalt(salt []byte) hash.Hash {
	d := new(digest512)
	d.is384 = true
	d.setSalt(salt)
	d.Reset()
	return d
}

// New512withSalt returns a new hash.Hash computing the BLAKE-512
// checksum but initializes with given 32-byte salt value.
func New512withSalt(salt []byte) hash.Hash {
	d := new(digest512)
	d.setSalt(salt)
	d.Reset()
	return d
}

// Sum224 returns the BLAKE-224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
	d := new(digest256)
	d.is224 = true
	d.Reset()
	d.Write(data)
	sum := d.checkSum()
	copy(sum224[:], sum[:Size224])
	return
}

// Sum256 returns the BLAKE-256 checksum of the data.
func Sum256(data []byte) [Size256]byte {
	var d digest256
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

// Sum384 returns the BLAKE-384 checksum of the data.
func Sum384(data []byte) (sum384 [Size384]byte) {
	var d digest512
	d.is384 = true
	d.Reset()
	d.Write(data)
	sum := d.checkSum()
	copy(sum384[:], sum[:Size384])
	return
}

// Sum512 returns the BLAKE-512 checksum of the data.
func Sum512(data []byte) [Size512]byte {
	var d digest512
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

// Sum224withSalt initializes with given 16-byte salt value
// and returns the BLAKE-224 checksum of the data.
func Sum224withSalt(data []byte, salt []byte) (sum224 [Size224]byte) {
	var d digest256
	d.is224 = true
	d.Reset()
	d.setSalt(salt)
	d.Write(data)
	sum := d.checkSum()
	copy(sum224[:], sum[:Size224])
	return
}

// Sum256withSalt initializes with given 16-byte salt value
// and returns the BLAKE-256 checksum of the data.
func Sum256withSalt(data []byte, salt []byte) [Size256]byte {
	var d digest256
	d.Reset()
	d.setSalt(salt)
	d.Write(data)
	return d.checkSum()
}

// Sum384withSalt initializes with given 32-byte salt value
// and returns the BLAKE-384 checksum of the data.
func Sum384withSalt(data []byte, salt []byte) (sum384 [Size384]byte) {
	var d digest512
	d.is384 = true
	d.Reset()
	d.setSalt(salt)
	d.Write(data)
	sum := d.checkSum()
	copy(sum384[:], sum[:Size384])
	return
}

// Sum512withSalt initializes with given 32-byte salt value
// and returns the BLAKE-512 checksum of the data.
func Sum512withSalt(data []byte, salt []byte) [Size512]byte {
	var d digest512
	d.Reset()
	d.setSalt(salt)
	d.Write(data)
	return d.checkSum()
}

func (d *digest256) Reset() {
	if d.is224 {
		d.h[0] = init0_224
		d.h[1] = init1_224
		d.h[2] = init2_224
		d.h[3] = init3_224
		d.h[4] = init4_224
		d.h[5] = init5_224
		d.h[6] = init6_224
		d.h[7] = init7_224
	} else {
		d.h[0] = init0_256
		d.h[1] = init1_256
		d.h[2] = init2_256
		d.h[3] = init3_256
		d.h[4] = init4_256
		d.h[5] = init5_256
		d.h[6] = init6_256
		d.h[7] = init7_256
	}
	d.t = 0
	d.nx = 0
	d.nullt = false
}

func (d *digest512) Reset() {
	if d.is384 {
		d.h[0] = init0_384
		d.h[1] = init1_384
		d.h[2] = init2_384
		d.h[3] = init3_384
		d.h[4] = init4_384
		d.h[5] = init5_384
		d.h[6] = init6_384
		d.h[7] = init7_384
	} else {
		d.h[0] = init0_512
		d.h[1] = init1_512
		d.h[2] = init2_512
		d.h[3] = init3_512
		d.h[4] = init4_512
		d.h[5] = init5_512
		d.h[6] = init6_512
		d.h[7] = init7_512
	}
	d.t = 0
	d.nx = 0
	d.nullt = false
}

func (d *digest256) Size() int {
	if d.is224 {
		return Size224
	}
	return Size256
}

func (d *digest512) Size() int {
	if d.is384 {
		return Size384
	}
	return Size512
}

func (d *digest256) BlockSize() int { return BlockSize256 }

func (d *digest512) BlockSize() int { return BlockSize512 }

func (d *digest256) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk256 {
			block256(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk256 {
		n := len(p) &^ (chunk256 - 1)
		block256(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest512) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk512 {
			block512(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk512 {
		n := len(p) &^ (chunk512 - 1)
		block512(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest256) checkSum() [Size256]byte {
	nx := uint64(d.nx)
	// Padding. Add a 1 bit and 0 bits until 55 bytes mod 64.
	var tmp [65]byte
	tmp[0] = 0x80
	len := d.t + nx<<3

	if nx == 55 {
		if d.is224 {
			d.writeAdditionalData([]byte{0x80})
		} else {
			d.writeAdditionalData([]byte{0x81})
		}
	} else {
		if nx < 55 {
			if nx == 0 {
				d.nullt = true
			}
			d.writeAdditionalData(tmp[0 : 55-nx])
		} else {
			d.writeAdditionalData(tmp[0 : 64-nx])
			d.writeAdditionalData(tmp[1:56])
			d.nullt = true
		}
		if d.is224 {
			d.writeAdditionalData([]byte{0x00})
		} else {
			d.writeAdditionalData([]byte{0x01})
		}
	}

	// Write  length in bits
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (56 - 8*i))
	}
	d.writeAdditionalData(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	h := d.h[:]
	if d.is224 {
		h = h[0:7]
	}

	var digest [Size256]byte
	for i, s := range h {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}
	return digest
}

func (d *digest256) writeAdditionalData(p []byte) {
	d.t -= uint64(len(p)) << 3
	d.Write(p)
}

func (d *digest512) checkSum() [Size512]byte {
	nx := uint64(d.nx)
	// Padding. Add a 1 bit and 0 bits until 110 bytes mod 124.
	var tmp [129]byte
	tmp[0] = 0x80
	len := d.t + nx<<3

	if nx == 111 {
		if d.is384 {
			d.writeAdditionalData([]byte{0x80})
		} else {
			d.writeAdditionalData([]byte{0x81})
		}
	} else {
		if nx < 111 {
			if nx == 0 {
				d.nullt = true
			}
			d.writeAdditionalData(tmp[0 : 111-nx])
		} else {
			d.writeAdditionalData(tmp[0 : 128-nx])
			d.writeAdditionalData(tmp[1:112])
			d.nullt = true
		}
		if d.is384 {
			d.writeAdditionalData([]byte{0x00})
		} else {
			d.writeAdditionalData([]byte{0x01})
		}
	}

	// Write  length in bits
	for i := uint(0); i < 16; i++ {
		tmp[i] = byte(len >> (120 - 8*i))
	}
	d.writeAdditionalData(tmp[0:16])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	h := d.h[:]
	if d.is384 {
		h = h[0:6]
	}

	var digest [Size512]byte
	for i, s := range h {
		digest[i*8] = byte(s >> 56)
		digest[i*8+1] = byte(s >> 48)
		digest[i*8+2] = byte(s >> 40)
		digest[i*8+3] = byte(s >> 32)
		digest[i*8+4] = byte(s >> 24)
		digest[i*8+5] = byte(s >> 16)
		digest[i*8+6] = byte(s >> 8)
		digest[i*8+7] = byte(s)
	}
	return digest
}

func (d *digest512) writeAdditionalData(p []byte) {
	d.t -= uint64(len(p)) << 3
	d.Write(p)
}

func (d0 *digest256) Sum(in []byte) []byte {
	d := new(digest256)
	*d = *d0
	hash := d.checkSum()
	if d.is224 {
		return append(in, hash[:Size224]...)
	}
	return append(in, hash[:]...)
}

func (d0 *digest512) Sum(in []byte) []byte {
	d := new(digest512)
	*d = *d0
	hash := d.checkSum()
	if d.is384 {
		return append(in, hash[:Size384]...)
	}
	return append(in, hash[:]...)
}

func (d *digest256) setSalt(s []byte) {
	if s != nil {
		if len(s) != 16 {
			panic("salt lenght must be 16 bytes")
		}
		for i, j := 0, 0; i < 4; i, j = i+1, j+4 {
			d.s[i] = uint32(s[j])<<24 | uint32(s[j+1])<<16 | uint32(s[j+2])<<8 | uint32(s[j+3])
		}
	}
}

func (d *digest512) setSalt(s []byte) {
	if s != nil {
		if len(s) != 32 {
			panic("salt lenght must be 32 bytes")
		}
		for i, j := 0, 0; i < 4; i, j = i+1, j+8 {
			d.s[i] = uint64(s[j])<<56 | uint64(s[j+1])<<48 | uint64(s[j+2])<<40 | uint64(s[j+3])<<32 | uint64(s[j+4])<<24 | uint64(s[j+5])<<16 | uint64(s[j+6])<<8 | uint64(s[j+7])
		}
	}
}
