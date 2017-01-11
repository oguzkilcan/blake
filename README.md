Package blake
=====================

	import "github.com/ouzklcn/blake"


Package blake implements SHA-3 finalist BLAKE-224, BLAKE-256, BLAKE-384 and BLAKE-512 hash functions.


Constants
---------

``` go
const Size224 = 28
```
The size, in bytes, of a BLAKE-224 checksum.

``` go
const Size256 = 32
```
The size, in bytes, of a BLAKE-256 checksum.

``` go
const Size384 = 48
```
The size, in bytes, of a BLAKE-384 checksum.

``` go
const Size512 = 64
```
The size, in bytes, of a BLAKE-512 checksum.

``` go
const BlockSize256 = 64
```
The block size, in bytes, of the BLAKE-224 and BLAKE-256 hash functions.

``` go
const BlockSize512 = 128
```
The block size, in bytes, of the BLAKE-384 and BLAKE-512 hash functions.


Functions
---------

### func New224

	func New() hash.Hash

New224 returns a new hash.Hash computing the BLAKE-512 checksum.

### func New256

	func New() hash.Hash

New256 returns a new hash.Hash computing the BLAKE-512 checksum.

### func New384

	func New384() hash.Hash

New384 returns a new hash.Hash computing the BLAKE-384 checksum.

### func New512

	func New512() hash.Hash

New512 returns a new hash.Hash computing the BLAKE-384 checksum.

### func New224withSalt

	func New224withSalt(salt []byte) hash.Hash

New224withSalt returns a new hash.Hash computing the BLAKE-224 checksum but initializes with given 16-byte salt value.

### func New256withSalt

	func New256withSalt(salt []byte) hash.Hash

New256withSalt returns a new hash.Hash computing the BLAKE-256 checksum but initializes with given 16-byte salt value.

### func New384withSalt

	func New384withSalt(salt []byte) hash.Hash

New384withSalt returns a new hash.Hash computing the BLAKE-384 checksum but initializes with given 32-byte salt value.

### func New512withSalt

	func New512withSalt(salt []byte) hash.Hash

New512withSalt returns a new hash.Hash computing the BLAKE-512 checksum but initializes with given 32-byte salt value.

### func Sum224

	func Sum224(data []byte) [Size224]byte

Sum224 returns the BLAKE-256 checksum of the data.

### func Sum256

	func Sum256(data []byte) [Size256]byte

Sum256 returns the BLAKE-256 checksum of the data.

### func Sum384

	func Sum384(data []byte) [Size384]byte

Sum384 returns the BLAKE-384 checksum of the data.

### func Sum512

	func Sum512(data []byte) [Size512]byte

Sum512 returns the BLAKE-512 checksum of the data.

### func Sum224withSalt

	func Sum224withSalt(data []byte, salt []byte) (sum224 [Size224]byte)

Sum224withSalt initializes with given 16-byte salt value and returns the BLAKE-224 checksum of the data. 

### func Sum256withSalt

	func Sum256withSalt(data []byte, salt []byte) [Size256]byte

Sum256withSalt initializes with given 16-byte salt value and returns the BLAKE-256 checksum of the data.

### func Sum384withSalt

	func Sum384withSalt(data []byte, salt []byte) (sum384 [Size384]byte)

Sum384withSalt initializes with given 32-byte salt value and returns the BLAKE-384 checksum of the data.

### func Sum512withSalt

	func Sum512withSalt(data []byte, salt []byte) [Size512]byte

Sum512withSalt initializes with given 32-byte salt value and returns the BLAKE-512 checksum of the data.