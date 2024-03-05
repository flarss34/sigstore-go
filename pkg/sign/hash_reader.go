package sign

import (
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
)

const (
	DefaultMaxWorkers int = 10
)

func FileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

// HashReader hashes while it reads.
type HashReader struct {
	r io.Reader
	h hash.Hash
}

func NewHashReader(r io.Reader, h hash.Hash) HashReader {
	return HashReader{
		r: io.TeeReader(r, h),
		h: h,
	}
}

// Read implements io.Reader.
func (h *HashReader) Read(p []byte) (n int, err error) { return h.r.Read(p) }

// Sum implements hash.Hash.
func (h *HashReader) Sum(p []byte) []byte { return h.h.Sum(p) }

// Reset implements hash.Hash.
func (h *HashReader) Reset() { h.h.Reset() }

// Size implements hash.Hash.
func (h *HashReader) Size() int { return h.h.Size() }

// BlockSize implements hash.Hash.
func (h *HashReader) BlockSize() int { return h.h.BlockSize() }

// Write implements hash.Hash
func (h *HashReader) Write(p []byte) (int, error) { return 0, errors.New("not implemented") } //nolint: revive
