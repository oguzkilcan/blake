package blake

import (
	"bytes"
	"fmt"
	"hash"
	"testing"
)

type blakeVector struct {
	out, in string
}

var vectors224 = []blakeVector{
	{"304c27fdbf308aea06955e331adc6814223a21fccd24c09fde9eda7b",
		"ube"},
	{"cfb6848add73e1cb47994c4765df33b8f973702705a30a71fe4747a3",
		"BLAKE"},
	{"7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed",
		""},
	{"8bd036c145222cd5401f36bcc79628b8d577f5e815910a71b92cb2be",
		"Golang"},
}

var vectors256 = []blakeVector{
	{"e802fe2a73fbe5853408f051d040aeb3a76a4d7a0fc5c3415d1af090f76a2c81",
		"ube"},
	{"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6",
		"BLAKE"},
	{"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
		""},
	{"61742eadc04f3911d7ee5c4213a9fe1f0816d4ebdab5d4ba406b7b6469cf0ed7",
		"Golang"},
}

var vectors384 = []blakeVector{
	{"8f22f120b2b99dd4fd32b98c8c83bd87abd6413f7317be936b1997511247fc68ae781c6f42113224ccbc1567b0e88593",
		"ube"},
	{"f28742f7243990875d07e6afcff962edabdf7e9d19ddea6eae31d094c7fa6d9b00c8213a02ddf1e2d9894f3162345d85",
		"BLAKE"},
	{"c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706",
		""},
	{"c8cb1692a7521667e3c613b7c3e10a8859e0f103f211db4f3842fff7fa4b86fac80910d24537f19f40f5a8051391d439",
		"Golang"},
}

var vectors512 = []blakeVector{
	{"49a24ca8f230936f938c19484d46b58f13ea4448ddadafecdf01419b1e1dd922680be2de84069187973ab61b10574da2ee50cbeaade68ea9391c8ec041b76be0",
		"ube"},
	{"7bf805d0d8de36802b882e65d0515aa7682a2be97a9d9ec1399f4be2eff7de07684d7099124c8ac81c1c7c200d24ba68c6222e75062e04feb0e9dd589aa6e3b7",
		"BLAKE"},
	{"a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8",
		""},
	{"cc6d779ca76673932e2f93681d502a1c6fd82932b48632c2a2f3c599e7bf016e7280a2e74da8a6fe76d5a36dd412ef7d67778acc1a458856f1181e9fe0a0c25c",
		"Golang"},
}

var vectors256salt = []struct{ out, in, salt string }{
	{"537a09933a7c457378cfaf91a49d2a25481a5b2ae9bae128e0d03b1cc7e76f8f",
		"ube",
		"1234567890123456"},
	{"b3b0021cc385f3e9ce43b498290cf6d9ab3ffe2c190b777a0e649af6c308a2d0",
		"BLAKE",
		"CRYPTOSYSTEMSand"},
}

var vectors512salt = []struct{ out, in, salt string }{
	{"288dd6574a6e79bb22f72d52b16d8be9360f1214aada2bb605dde838d54a75d7bba46852c1aad56bc16a9ac37c5ffbc43978cadc1666ac82a79289a6b9a52793",
		"ube",
		"12345678901234561234567890123456"},
	{"d047341e3d82a6f4efdca3f877a0baf193275d64bd79020d21ab945c3e75a71d9885cd87084909c859f398dd533e517965d2a96e15c14ad44f070ce159cf6180",
		"BLAKE",
		"CRYPTOSYSTEMSandCRYPTOGRAPHICPRO"},
}

func testNew(t *testing.T, hashfunc func() hash.Hash, vectors []blakeVector) {
	for i, v := range vectors {
		h := hashfunc()
		h.Write([]byte(v.in))
		res := fmt.Sprintf("%x", h.Sum(nil))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestNew224(t *testing.T) {
	testNew(t, New224, vectors224)
}

func TestNew256(t *testing.T) {
	testNew(t, New256, vectors256)
}

func TestNew384(t *testing.T) {
	testNew(t, New384, vectors384)
}

func TestNew512(t *testing.T) {
	testNew(t, New512, vectors512)
}

func TestSum224(t *testing.T) {
	for i, v := range vectors224 {
		res := fmt.Sprintf("%x", Sum224([]byte(v.in)))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestSum256(t *testing.T) {
	for i, v := range vectors256 {
		res := fmt.Sprintf("%x", Sum256([]byte(v.in)))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestSum384(t *testing.T) {
	for i, v := range vectors384 {
		res := fmt.Sprintf("%x", Sum384([]byte(v.in)))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestSum512(t *testing.T) {
	for i, v := range vectors512 {
		res := fmt.Sprintf("%x", Sum512([]byte(v.in)))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestSalt256(t *testing.T) {
	for i, v := range vectors256salt {
		h := New256withSalt([]byte(v.salt))
		h.Write([]byte(v.in))
		res := fmt.Sprintf("%x", h.Sum(nil))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}

	// Check that passing bad salt length panics.
	defer func() {
		if err := recover(); err == nil {
			t.Error("expected panic for bad salt length")
		}
	}()
	New256withSalt([]byte{1, 2, 3, 4, 5, 6, 7, 8})
}

func TestSalt512(t *testing.T) {
	for i, v := range vectors512salt {
		h := New512withSalt([]byte(v.salt))
		h.Write([]byte(v.in))
		res := fmt.Sprintf("%x", h.Sum(nil))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}

	// Check that passing bad salt length panics.
	defer func() {
		if err := recover(); err == nil {
			t.Error("expected panic for bad salt length")
		}
	}()
	New512withSalt([]byte{1, 2, 3, 4, 5, 6, 7, 8})
}

func TestTwoWrites(t *testing.T) {
	b := []byte("Testing123")
	h1 := New256()
	h1.Write(b[:1])
	h1.Write(b[1:])
	sum1 := h1.Sum(nil)

	h2 := New256()
	h2.Write(b)
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Error("Result of two writes differs from a single write with the same bytes")
	}

	h3 := New512()
	h3.Write(b[:3])
	h3.Write(b[3:])
	sum3 := h3.Sum(nil)

	h4 := New512()
	h4.Write(b)
	sum4 := h4.Sum(nil)

	if !bytes.Equal(sum3, sum4) {
		t.Error("Result of two writes differs from a single write with the same bytes")
	}
}
