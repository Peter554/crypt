# crypt

[![CI](https://github.com/Peter554/crypt/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Peter554/crypt/actions/workflows/ci.yml)

CLI for encryption and decryption of documents.

I am not a crypto expert - *use at your own peril*!

- *Initialisation*. The vault is initialised with a password. A hash of this password is stored for later comparison (bcrypt). From this password we derive a root key, via a key derivation function (Argon2). We then generate a random document key, which will be used later for encryption/decryption of documents. We encrypt the document key using the root key, and store the result for later use.

- *Encryption/decryption*. To encrypt/decrypt a document we need the unencrypted root key. This is obtained by first requesting the user for the vault password. If the provided password is correct (compare with stored hash) the root key is again derived from the password and used to decrypt the stored, encrypted document key. Once the unencrypted document key is obtained the document is simply encrypted/decrypted using this key (Advanced Encryption Standard, Galois Counter Mode).

- *Change password*. Having both a password derived root key and a document key makes it relatively simple to change the vault password. Changing the vault password involves decryption of the root key using the old password and re-encryption using the new password. There is no need to re-encrypt documents!

```
> crypt help

Usage: crypt <command>

CLI for encryption and decryption of documents.

Commands:

* init

  crypt init

  Initialise the crypt vault.

* encrypt

  crypt encrypt <srcpath> [dstpath]

  Encrypt the document at srcpath and store the result at dstpath.
  dstpath defaults to srcpath+".crypt".

* decrypt

  crypt decrypt <srcpath> <dstpath>

  Decrypt the document at srcpath and store the result at dstpath.

* change_password

  crypt change_password

  Change the crypt vault password.  

* help

  crypt help

  Print this help. 
```