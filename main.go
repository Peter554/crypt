package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

// ErrWrongPassword indicates an invalid password was passed
var ErrWrongPassword = errors.New("wrong password")

func main() {
	home, err := homedir.Dir()
	if err != nil {
		log.Fatal(err)
	}
	cryptDir := filepath.Join(home, ".crypt")
	err = os.Mkdir(cryptDir, 0770)
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		Help()
		return
	}

	run := func() error {
		switch os.Args[1] {
		case "init":
			pw, err := readPasswordWithConfirm("password")
			if err != nil {
				return err
			}
			return Initialise(cryptDir, pw, nil)
		case "encrypt":
			pw, err := readPassword("password")
			if err != nil {
				return err
			}
			return Encrypt(os.Args[2:], cryptDir, pw)
		case "decrypt":
			pw, err := readPassword("password")
			if err != nil {
				return err
			}
			return Decrypt(os.Args[2:], cryptDir, pw)
		case "change_password":
			pwOld, err := readPassword("old password")
			if err != nil {
				return err
			}
			pwNew, err := readPasswordWithConfirm("new password")
			if err != nil {
				return err
			}
			return ChangePassword(cryptDir, pwOld, pwNew)
		case "help":
			Help()
			return nil
		default:
			Help()
			return nil
		}
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// Help prints usage information
func Help() {
	fmt.Print(`
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
`)
}

// Initialise initialises the crypt vault
func Initialise(cryptDir string, pw, key1 []byte) error {
	pwHash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(cryptDir, "pw"))
	if err != nil {
		return err
	}
	_, err = f.Write(pwHash)
	if err != nil {
		return err
	}

	if key1 == nil {
		key1 = make([]byte, 32)
		_, err = rand.Read(key1)
		if err != nil {
			return err
		}
	}

	key0 := deriveKey0(pw)
	key1Encrypted, err := encrypt(key0, key1)
	if err != nil {
		return err
	}

	f, err = os.Create(filepath.Join(cryptDir, "key"))
	if err != nil {
		return err
	}
	_, err = f.Write(key1Encrypted)
	return err
}

// Encrypt encrypts a document
func Encrypt(args []string, cryptDir string, pw []byte) error {
	ok, err := checkPassword(cryptDir, pw)
	if err != nil {
		return err
	}
	if !ok {
		return ErrWrongPassword
	}

	key1, err := decryptKey1(cryptDir, pw)
	if err != nil {
		return err
	}

	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	plaintext, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	b, err := encrypt(key1, plaintext)
	if err != nil {
		return err
	}

	dstPath := args[0] + ".crypt"
	if len(args) > 1 {
		dstPath = args[1]
	}
	f, err = os.Create(dstPath)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return err
}

// Decrypt decrypts a document
func Decrypt(args []string, cryptDir string, pw []byte) error {
	ok, err := checkPassword(cryptDir, pw)
	if err != nil {
		return err
	}
	if !ok {
		return ErrWrongPassword
	}

	key1, err := decryptKey1(cryptDir, pw)
	if err != nil {
		return err
	}

	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(key1, ciphertext)
	if err != nil {
		return err
	}

	f, err = os.Create(args[1])
	if err != nil {
		return err
	}
	_, err = f.Write(plaintext)
	return err
}

// ChangePassword changes the crypt vault password.
// Documents do not need to be re-encrypted.
func ChangePassword(cryptDir string, pwOld, pwNew []byte) error {
	ok, err := checkPassword(cryptDir, pwOld)
	if err != nil {
		return err
	}
	if !ok {
		return ErrWrongPassword
	}

	key1, err := decryptKey1(cryptDir, pwOld)
	if err != nil {
		return err
	}

	return Initialise(cryptDir, pwNew, key1)
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Printf("\n%s: ", prompt)
	return terminal.ReadPassword(syscall.Stdin)
}

func readPasswordWithConfirm(prompt string) ([]byte, error) {
	fmt.Printf("\n%s: ", prompt)
	pw, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Printf("\n%s (confirm): ", prompt)
	pwConfirm, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	if len(pw) != len(pwConfirm) {
		return nil, errors.New("passwords did not match")
	}
	for idx, b := range pw {
		if b != pwConfirm[idx] {
			return nil, errors.New("passwords did not match")
		}
	}
	return pw, err
}

func checkPassword(cryptDir string, pw []byte) (bool, error) {
	f, err := os.Open(filepath.Join(cryptDir, "pw"))
	if err != nil {
		return false, err
	}
	h, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	return bcrypt.CompareHashAndPassword(h, pw) == nil, nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

func deriveKey0(pw []byte) []byte {
	return argon2.IDKey(pw, []byte("key"), 1, 64*1024, 4, 32)
}

func decryptKey1(cryptDir string, pw []byte) ([]byte, error) {
	f, err := os.Open(filepath.Join(cryptDir, "key"))
	if err != nil {
		return nil, err
	}
	key1Encrypted, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	key0 := deriveKey0(pw)
	return decrypt(key0, key1Encrypted)
}
