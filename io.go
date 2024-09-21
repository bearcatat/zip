package zip

import (
	"errors"
	"io"
	"log"
	"sync"
)

type RewindReader struct {
	mu         sync.Mutex
	rawReader  io.Reader
	buf        []byte
	bufReadIdx int
	rewound    bool
	buffering  bool
	bufferSize int
	readIdx    int64
}

func (r *RewindReader) Read(p []byte) (int, error) {
	n, err := r.read(p)
	r.readIdx += int64(n)
	return n, err
}

func (r *RewindReader) read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.rewound {
		if len(r.buf) > r.bufReadIdx {
			n := copy(p, r.buf[r.bufReadIdx:])
			r.bufReadIdx += n
			return n, nil
		}
		r.rewound = false // all buffering content has been read
	}
	n, err := r.rawReader.Read(p)
	if r.buffering {
		r.buf = append(r.buf, p[:n]...)
		if len(r.buf) > r.bufferSize*2 {
			log.Println("read too many bytes!")
		}
	}
	return n, err
}

func (r *RewindReader) ReadByte() (byte, error) {
	b, err := r.readByte()
	r.readIdx++
	return b, err
}

func (r *RewindReader) readByte() (byte, error) {
	buf := [1]byte{}
	_, err := r.Read(buf[:])
	return buf[0], err
}

func (r *RewindReader) Discard(n int) (int, error) {
	n, err := r.discard(n)
	r.readIdx += int64(n)
	return n, err
}

func (r *RewindReader) discard(n int) (int, error) {
	buf := [128]byte{}
	if n < 128 {
		return r.Read(buf[:n])
	}
	for discarded := 0; discarded+128 < n; discarded += 128 {
		_, err := r.Read(buf[:])
		if err != nil {
			return discarded, err
		}
	}
	if rest := n % 128; rest != 0 {
		return r.Read(buf[:rest])
	}
	return n, nil
}

func (r *RewindReader) Seek(offset int64, whence int) (int64, error) {
	if whence != 0 {
		return 0, errors.New("unsupported whence")
	}
	if offset < int64(r.readIdx) {
		return 0, errors.New("offset is less than readIdx")
	}
	discard := offset - r.readIdx
	if discard > 0 {
		_, err := r.Discard(int(discard))
		if err != nil {
			return 0, err
		}
	}
	return offset, nil
}

func (r *RewindReader) Rewind() {
	r.mu.Lock()
	if r.bufferSize == 0 {
		panic("no buffer")
	}
	r.rewound = true
	r.bufReadIdx = 0
	r.readIdx -= int64(len(r.buf))
	r.mu.Unlock()
}

func (r *RewindReader) StopBuffering() {
	r.mu.Lock()
	r.buffering = false
	r.mu.Unlock()
}

func (r *RewindReader) SetBufferSize(size int) {
	r.mu.Lock()
	if size == 0 { // disable buffering
		if !r.buffering {
			panic("reader is disabled")
		}
		r.buffering = false
		r.buf = nil
		r.bufReadIdx = 0
		r.bufferSize = 0
	} else {
		if r.buffering {
			panic("reader is buffering")
		}
		r.buffering = true
		r.bufReadIdx = 0
		r.bufferSize = size
		r.buf = make([]byte, 0, size)
	}
	r.mu.Unlock()
}
