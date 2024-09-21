package zip

import (
	"bufio"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"sort"

	"go4.org/readerutil"
)

type ZipFileReader interface {
	io.Seeker
	io.Reader
	readerutil.SizeReaderAt
}

type FastReader struct {
	r     *RewindReader
	files []*FastFile
}

func NewFastReader(zipReaders []ZipFileReader) (*FastReader, error) {
	z := &FastReader{}
	if err := z.init(zipReaders); err != nil {
		return nil, err
	}
	return z, nil
}

func (z *FastReader) WalkDir(fn func(f *FastFile)) {
	for _, file := range z.files {
		fn(file)
	}
}

func (z *FastReader) init(zipReaders []ZipFileReader) error {
	sizedReaderAt := make([]readerutil.SizeReaderAt, 0, len(zipReaders))
	volumeSizes := make([]int64, 0, len(zipReaders))
	for _, r := range zipReaders {
		sizedReaderAt = append(sizedReaderAt, r)
		volumeSizes = append(volumeSizes, r.Size())
	}
	multiReaderAt := readerutil.NewMultiReaderAt(sizedReaderAt...)
	size := multiReaderAt.Size()

	end, err := readDirectoryEnd(multiReaderAt, size, volumeSizes...)
	if err != nil {
		return err
	}

	z.files = make([]*FastFile, 0, end.directoryRecords)

	rs := io.NewSectionReader(multiReaderAt, 0, size)
	if _, err = rs.Seek(int64(end.directoryOffset), os.SEEK_SET); err != nil {
		return err
	}

	buf := bufio.NewReader(rs)
	for {
		f := &File{}
		err = readDirectoryHeader(f, buf, volumeSizes...)
		if err == ErrFormat || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}

		z.files = append(z.files, &FastFile{
			FileHeader:   f.FileHeader,
			headerOffset: f.headerOffset,
			zipR:         z,
		})
	}
	sort.Slice(z.files, func(i, j int) bool {
		return z.files[i].headerOffset < z.files[j].headerOffset
	})

	readers := make([]io.Reader, 0, len(zipReaders))
	for _, r := range zipReaders {
		if _, err := r.Seek(0, 0); err != nil {
			return err
		}
		readers = append(readers, r)
	}
	rewindReader := &RewindReader{rawReader: io.MultiReader(readers...)}

	z.r = rewindReader
	return nil
}

type FastFile struct {
	FileHeader
	headerOffset int64
	zipR         *FastReader
}

func (f *FastFile) Open() (rc io.ReadCloser, err error) {
	discardSize, err := f.findBodyOffset()
	if err != nil {
		return
	}
	_, err = f.zipR.r.Discard(int(discardSize))
	if err != nil {
		return
	}
	size := int64(f.CompressedSize64)
	var r io.Reader
	rr := io.LimitReader(f.zipR.r, size)
	// check for encryption
	if f.IsEncrypted() {
		if f.ae == 0 {
			if r, err = NewZipCryptoReader(rr, f.password()); err != nil {
				return
			}
		} else if r, err = newFastDecryptionReader(rr, &f.FileHeader); err != nil {
			return
		}
	} else {
		r = rr
	}
	dcomp := decompressor(f.Method)
	if dcomp == nil {
		err = ErrAlgorithm
		return
	}
	rc = dcomp(r)
	if f.isAE2() {
		return
	}
	var descOff int64
	if f.hasDataDescriptor() {
		descOff = f.headerOffset + fileHeaderLen + discardSize + size
	}

	rc = &fastFileReader{
		rc:      rc,
		raw:     f.zipR.r,
		descOff: descOff,
		hash:    crc32.NewIEEE(),
		f:       f,
	}

	return
}

func (f *FastFile) findBodyOffset() (int64, error) {
	var buf [fileHeaderLen]byte
	if _, err := f.zipR.r.Seek(f.headerOffset, 0); err != nil {
		return 0, err
	}
	if _, err := f.zipR.r.Read(buf[:]); err != nil {
		return 0, err
	}
	b := readBuf(buf[:])
	if sig := b.uint32(); sig != fileHeaderSignature {
		return 0, ErrFormat
	}
	b = b[22:] // skip most of the header
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())

	return int64(filenameLen + extraLen), nil
}

func (f *FastFile) hasDataDescriptor() bool {
	return f.Flags&0x8 != 0
}

type fastFileReader struct {
	rc      io.ReadCloser
	raw     *RewindReader
	descOff int64
	hash    hash.Hash32
	nread   uint64
	f       *FastFile
	err     error
}

// Close implements io.ReadCloser.
func (f *fastFileReader) Close() error {
	return f.rc.Close()
}

// Read implements io.ReadCloser.
func (r *fastFileReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err = r.rc.Read(p)
	r.hash.Write(p[:n])
	r.nread += uint64(n)
	if err == nil {
		return
	}
	if err == io.EOF {
		if r.nread != r.f.UncompressedSize64 {
			return 0, io.ErrUnexpectedEOF
		}
		if r.descOff > 0 {
			if err1 := r.readDataDescriptor(); err1 != nil {
				if err1 == io.EOF {
					err = io.ErrUnexpectedEOF
				} else {
					err = err1
				}
			} else if r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		} else if r.f.CRC32 != 0 && r.hash.Sum32() != r.f.CRC32 {
			err = ErrChecksum
		}
	}
	r.err = err
	return
}

func (r *fastFileReader) readDataDescriptor() error {
	if _, err := r.raw.Seek(r.descOff, 0); err != nil {
		return err
	}
	r.raw.SetBufferSize(dataDescriptorLen)
	defer r.raw.StopBuffering()

	var buf [dataDescriptorLen]byte
	if _, err := io.ReadFull(r.raw, buf[:]); err != nil {
		return err
	}

	off := 0
	maybeSig := readBuf(buf[:4])
	maybeSigUint32 := maybeSig.uint32()
	if maybeSigUint32 != dataDescriptorSignature {
		// No data descriptor signature. Keep these four
		// bytes.
		if maybeSigUint32 == fileHeaderSignature || maybeSigUint32 == directoryHeaderSignature {
			r.raw.Rewind()
			r.raw.StopBuffering()
			return nil
		}
		off += 4
	}
	if _, err := io.ReadFull(r.raw, buf[off:12]); err != nil {
		return err
	}
	b := readBuf(buf[:12])
	if b.uint32() != r.f.CRC32 {
		return ErrChecksum
	}
	return nil
}
