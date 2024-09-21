package zip

import "io"

type ZipReader interface {
	io.Seeker
	io.Reader
	io.ReaderAt
}

type FastReader struct {
	reader *RewindReader
	Files  []*FastFile
}

func (z *FastReader) init(r []ZipReader, size int64, volumeSizes ...int64) error {
	end, err := read
}

type FastFile struct {
}
