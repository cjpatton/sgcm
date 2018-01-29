This package adds enhancements to Go's implementation of Galois counter mode
authenticated encryption. Specifically, it adds two features: online encryption,
decryption, and verification (meaning the operation does one pass of the
plaintext or ciphertext), and the ability to efficiently "fast-forward" the key
stream so as to facilitate random access of the ciphertext.

See LICENSE in this directory for terms of use.
