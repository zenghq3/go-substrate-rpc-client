package blake2b

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

// New128Concat returns a new hash.Hash computing the concat(BLAKE2b-128 checksum(key), key).
// A non-nil key turns the hash into a MAC. The key must be between zero and 64 bytes long.
func New128Concat(key []byte) (hash.Hash, error) {
	h, err := blake2b.New(16, key)
	if err != nil {
		return nil, err
	}

	return &digestConcat128{
		hasher: h,
		data:   key,
	}, nil
}

type digestConcat128 struct {
	hasher hash.Hash
	data   []byte
}

func (d *digestConcat128) BlockSize() int {
	return d.hasher.BlockSize()
}

func (d *digestConcat128) Size() int {
	return d.hasher.Size()
}

func (d *digestConcat128) Reset() {
	d.data = make([]byte, 0)
	d.hasher.Reset()
}

func (d *digestConcat128) Write(p []byte) (n int, err error) {
	d.data = append(d.data, p...)
	return d.hasher.Write(p)
}

func (d *digestConcat128) Sum(sum []byte) (r []byte) {
	return append(d.hasher.Sum(sum), d.data...)
}
