package sgcm

import (
	"crypto/cipher"
	"crypto/subtle"
)

// AEADEncryptor is an AEAD interface specialized for streaming
// encryption. Its API is inspired by online AE (as described by Hoang et al.,
// see https://eprint.iacr.org/2015/189.pdf).
type AEADEncryptor interface {

	// TagSize() returns the ciphertext expansion. Unlike the AEAD interface,
	// this is required to be constant.
	TagSize() int

	// Initialize sets up the state for encryption using the nonce and
	// associated data.
	Initialize(nonce, ad []byte)

	// Next takes as input the next fragment of plaintext, appends the
	// corresponding ciphertext fragment to dst, and returns the updated slice.
	//
	// The implementation may buffer ciphertext. It is also not guranteed that
	// the length of the slice appended to dst is equal to the length of src.
	Next(dst, src []byte) []byte

	// Finalize treats the input src as the last fragment of plaintext, computes
	// the tag for the ciphertext just processed, appends it to dst (along with
	// any ciphrtext still in the buffer), and returns the updated slice. The
	// tag is of length TagSize().
	Finalize(dst []byte) []byte
}

// AEADDecryptor is an AEAD interface specialized for streaming decryption. It
// may be also be used to verify the ciphertext only and not output the
// corresponding plaintext.
//
// WARNING: When used to decrypt, the implementation is not required to prevent
// release of unverified plaintext.
type AEADDecryptor interface {

	// TagSize() returns the ciphertext expansion. Unlike the AEAD interface,
	// this is required to be constant.
	TagSize() int

	// Initialize sets up the state for decryption using the specified nonce and
	// associated data.
	Initialize(nonce, ad []byte)

	// InitializeVerify sets up the state for verification only.
	InitializeVerifyOnly(nonce, ad []byte)

	// Next takes as input the next fragment of ciphertext. If the state was
	// initialized with Initialize(), then it appends the corresponding
	// plaintext fragment to dst and returns the updated slice if the state was
	// initiialzed with InitializeVerifyOnly(), then it outputs dst without
	// modification.
	Next(dst, src []byte) []byte

	// FinalizeDecrypt takes as input the tag and uses it to authenticate the
	// ciphertext just processed and returns an indication of whether the
	// ciphertext is authentic. If the state was initialized with Initialize(),
	// then the any plaintext still in the buffer is appended to dst and
	// returend; otherwise, just dst is returned.
	//
	// Note a minor asymmetry between streaming encryption and decryption: the
	// decrypting party needs to know the length of the ciphertext before
	// processing it so that the tag is processed correctly. If any of the tag
	// is inadvertently processed by Next(), then Decrypt() will
	// output an error.
	//
	// The implementation should panic if Initalize() has not been
	// called.
	Finalize(dst, tag []byte) ([]byte, error)
}

type gcmStreamer struct {
	gcm
	y, z             gcmFieldElement
	counter, tagMask [gcmBlockSize]byte
	buf              []byte
	verifyOnly       bool
}

type gcmEncryptor struct {
	gcmStreamer
}

type gcmDecryptor struct {
	gcmStreamer
}

// NewStreamingGCM returns an AEADEncryptor and AEADDecryptor implemented
// using a blockcipher in Galois counter Mode using the standard (12 byte) nonce
// size.
//
// The input cipher must a have a blocksize of 16 bytes, e.g AES-128.
func NewStreamingGCM(cipher cipher.Block) (AEADEncryptor, AEADDecryptor, error) {
	return NewStreamingGCMWithNonceSize(cipher, gcmStandardNonceSize)
}

// NewStreamingGCMWithNoncSize returns an AEADEncryptor and AEADDecryptor for
// Galois counter mode with a non-standard nonce size.
func NewStreamingGCMWithNonceSize(cipher cipher.Block, size int) (AEADEncryptor, AEADDecryptor, error) {
	g, err := NewGCMWithNonceSize(cipher, size)
	if err != nil {
		return nil, nil, err
	}
	sg := &gcmStreamer{
		*(g.(*gcm)),
		gcmFieldElement{},
		gcmFieldElement{},
		[16]byte{},
		[16]byte{},
		nil,
		false,
	}

	enc := &gcmEncryptor{*sg}
	dec := &gcmDecryptor{*sg}
	return enc, dec, nil
}

func (sg *gcmStreamer) TagSize() int {
	return gcmTagSize
}

// Initialize sets up the state for streaming encryption/decryption in Galois
// counter mode.
func (sg *gcmStreamer) Initialize(nonce, ad []byte) {
	if len(nonce) != sg.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	for i := range sg.counter {
		sg.counter[i] = 0
	}
	sg.deriveCounter(&sg.counter, nonce, 1)

	sg.cipher.Encrypt(sg.tagMask[:], sg.counter[:])
	gcmInc32(&sg.counter)

	sg.y.low = 0
	sg.y.high = 0
	sg.z.low = uint64(len(ad)) * 8
	sg.z.high = 0 // This is len(ciphertext) * 8
	sg.update(&sg.y, ad)

	sg.buf = nil
}

// Finalize the computation of the ciphertext tag.
//
// Expects that len(t) >= 16.
func (sg *gcmStreamer) finalizeAuth(t []byte) {
	sg.z.high *= 8
	sg.y.high ^= sg.z.high
	sg.y.low ^= sg.z.low
	sg.mul(&sg.y)
	putUint64(t, sg.y.low)
	putUint64(t[8:], sg.y.high)
	xorWords(t, t, sg.tagMask[:])
}

// Next buffers the input until at least one complete block is available. If so,
// it encrypt its as many full blocks as are available and appends the
// ciphertext to dst, leaving any remaining bytes in the buffer; otherwise it
// just outputs dst.
func (enc *gcmEncryptor) Next(dst, src []byte) []byte {

	// Buffer plaintext fragment src and update the ciphertext length
	// (enc.z.hight).
	enc.buf = append(enc.buf, src...)
	enc.z.high += uint64(len(src))

	if enc.z.high > ((1<<32)-2)*uint64(enc.cipher.BlockSize()) {
		panic("cipher: message too large for GCM")
	}

	// Encrypt and consume all available blocks.
	bytes := (len(enc.buf) >> 4) << 4
	if bytes > 0 {
		// Encrypt full blocks.
		c := make([]byte, bytes)
		enc.counterCrypt(c, enc.buf[:bytes], &enc.counter)

		// Remove encrypted blocks from the buffer.
		enc.buf = enc.buf[bytes:]

		// Update the authenticator state.
		enc.update(&enc.y, c)

		// Append the ciphertext to dst.
		dst = append(dst, c...)
	}

	return dst
}

// Finalize encrypts any data left in the buffer, computes the tag for the
// ciphertext, and appends the remaining ciphertext and tag to dst and returns
// it.
func (enc *gcmEncryptor) Finalize(dst []byte) []byte {

	// Encrypt the last chunk and update the authenticator.
	c := make([]byte, len(enc.buf))
	enc.cipher.Encrypt(enc.counter[:], enc.counter[:])
	xorBytes(c, enc.buf, enc.counter[:])
	enc.update(&enc.y, c)
	dst = append(dst, c...)

	// Finalize the authenticator.
	t := make([]byte, gcmTagSize)
	enc.finalizeAuth(t)

	dst = append(dst, t...)
	return dst
}

// InitializeVerifyOnly sets up decryption state in "authenticate only" mode.
// This means that the ciphertext is processed like normal, except that no
// plaintext is output by Next() or Finalize().
func (dec *gcmDecryptor) InitializeVerifyOnly(nonce, ad []byte) {
	dec.Initialize(nonce, ad)
	dec.verifyOnly = true
}

// Next buffers the input until at least one complete block is available,
// decrypts, and appends the result to dst.
func (dec *gcmDecryptor) Next(dst, src []byte) []byte {

	// Buffer ciphertext fragment src and update the ciphertext length
	// (dec.z.hight).
	dec.buf = append(dec.buf, src...)
	dec.z.high += uint64(len(src))

	// Encrypt and consume all available blocks.
	bytes := (len(dec.buf) >> 4) << 4
	if bytes > 0 {
		// Update the authenticator state with the ciphertext fragment.
		dec.update(&dec.y, dec.buf[:bytes])

		// Decrypt full blocks.
		if !dec.verifyOnly {
			p := make([]byte, bytes)
			dec.counterCrypt(p, dec.buf[:bytes], &dec.counter)

			// Append the ciphertext to dst.
			dst = append(dst, p...)
		}

		// Remove decrypted blocks from the buffer.
		dec.buf = dec.buf[bytes:]
	}

	return dst
}

// Finalize decrypts any remaining cipehrtext and appends it to dst.
// It then computes the tag for the ciphertext just processed and checks that
// it is equal to the tag provided by the caller. If the ciphertext is
// authentic, then it outputs dst; otherwise it outputs nil and an error.
func (dec *gcmDecryptor) Finalize(dst, tag []byte) ([]byte, error) {
	// Update the authenticator state with the remaining fragment.
	dec.update(&dec.y, dec.buf)

	// Decrypt the last fragment.
	if !dec.verifyOnly {
		p := make([]byte, len(dec.buf))
		dec.cipher.Encrypt(dec.counter[:], dec.counter[:])
		xorBytes(p, dec.buf, dec.counter[:])
		dst = append(dst, p...)
	}

	// Finalize the authenticator.
	t := make([]byte, gcmTagSize)
	dec.finalizeAuth(t)

	// Check validity of the tag.
	//
	// (See gcm.go:210 for an explanation of the inner for-loop.)
	if subtle.ConstantTimeCompare(tag, t) != 1 {
		for i := range t {
			t[i] = 0
		}
		return nil, errOpen
	}

	return dst, nil
}
