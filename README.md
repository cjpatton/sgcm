This package adds enhancements to Go's implementation of Galois counter mode
authenticated encryption. Specifically, it adds two features: online encryption,
decryption, and verification (meaning the operation does one pass of the
plaintext or ciphertext), and the ability to efficiently "fast-forward" the key
stream so as to facilitate random access of the ciphertext.

Much of this code comes from the Go project; see LICENSE in this directory for
terms of use. For a summary of changes, have a look at:
https://github.com/golang/go/compare/master...cjpatton:master

TODO(cjpatton)
  * Change TagSize() to Overhead() in AEADEncryptor and AEADDecryptor interfaces.
  * Improve test coverage. (The original code does not have test vectors for
    extended nonces.)
