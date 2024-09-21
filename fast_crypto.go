package zip

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"hash"
	"io"
)

func newFastDecryptionReader(r io.Reader, header *FileHeader) (io.Reader, error) {
	rewindReader := &RewindReader{rawReader: r}

	keyLen := aesKeyLen(header.aesStrength)
	saltLen := keyLen / 2
	if saltLen == 0 {
		return nil, ErrDecryption
	}

	saltpwvv := make([]byte, saltLen+2)
	rewindReader.SetBufferSize(saltLen + 2)
	if _, err := rewindReader.Read(saltpwvv); err != nil {
		return nil, err
	}
	rewindReader.Rewind()
	rewindReader.StopBuffering()

	salt := saltpwvv[:saltLen]
	pwvv := saltpwvv[saltLen : saltLen+2]
	decKey, authKey, pwv := generateKeys(header.password(), salt, keyLen)
	if !checkPasswordVerification(pwv, pwvv) {
		return nil, ErrPassword
	}

	dataOff := int64(saltLen + 2)
	dataLen := int64(header.CompressedSize64 - uint64(saltLen) - 2 - 10)

	rewindReader.Seek(dataOff, 0)
	data := io.LimitReader(rewindReader, dataLen)
	authOff := dataOff + dataLen
	ar := newFastAuthReader(authKey, data, rewindReader, authOff)
	dr := decryptStream(decKey, ar)
	if dr == nil {
		return nil, ErrDecryption
	}
	return dr, nil
}

func newFastAuthReader(akey []byte, data io.Reader, raw *RewindReader, authOff int64) io.Reader {
	return &fastAuthReader{
		data:    data,
		raw:     raw,
		authOff: authOff,
		mac:     hmac.New(sha1.New, akey),
		err:     nil,
		auth:    false,
	}
}

type fastAuthReader struct {
	data    io.Reader
	raw     *RewindReader
	authOff int64
	mac     hash.Hash
	err     error
	auth    bool
}

func (a *fastAuthReader) Read(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	end := false
	// read underlying data
	n, err := a.data.Read(p)
	if err != nil && err != io.EOF {
		a.err = err
		return n, a.err
	} else if err == io.EOF {
		// if we are at the end, calculate the mac
		end = true
		a.err = err
	}
	// write any data to mac
	_, err = a.mac.Write(p[:n])
	if err != nil {
		a.err = err
		return n, a.err
	}
	if end {
		_, err := a.raw.Seek(a.authOff, 0)
		if err != nil {
			a.err = err
			return n, a.err
		}
		adata := io.LimitReader(a.raw, 10)

		ab := new(bytes.Buffer)
		_, err = io.Copy(ab, adata)
		if err != nil || ab.Len() != 10 {
			a.err = ErrDecryption
			return n, a.err
		}
		if !a.checkAuthentication(ab.Bytes()) {
			a.err = ErrAuthentication
			return n, a.err
		}
	}
	return n, a.err
}

func (a *fastAuthReader) checkAuthentication(authcode []byte) bool {
	expectedAuthCode := a.mac.Sum(nil)
	// Truncate at the first 10 bytes
	expectedAuthCode = expectedAuthCode[:10]
	a.auth = subtle.ConstantTimeCompare(expectedAuthCode, authcode) > 0
	return a.auth
}
