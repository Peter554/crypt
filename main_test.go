package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	cryptDir, err := ioutil.TempDir("", "crypt_crypt")
	require.Nil(t, err)
	defer os.RemoveAll(cryptDir)

	pw := []byte("Password1!!")

	err = Initialise(cryptDir, pw, nil)
	require.Nil(t, err)

	filesDir, err := ioutil.TempDir("", "crypt_files")
	require.Nil(t, err)
	defer os.RemoveAll(filesDir)
	fp := filepath.Join(filesDir, "hello_crypt")
	f, err := os.Create(fp)
	require.Nil(t, err)
	_, err = f.Write([]byte("hello crypt!"))
	require.Nil(t, err)

	err = Encrypt([]string{fp, fp + ".crypt"}, cryptDir, pw)
	require.Nil(t, err)

	err = Decrypt([]string{fp + ".crypt", fp + ".out"}, cryptDir, pw)
	require.Nil(t, err)

	f, err = os.Open(fp + ".out")
	require.Nil(t, err)
	b, err := ioutil.ReadAll(f)
	require.Nil(t, err)
	require.Equal(t, []byte("hello crypt!"), b)
}

func TestChangePassword(t *testing.T) {
	cryptDir, err := ioutil.TempDir("", "crypt_crypt")
	require.Nil(t, err)
	defer os.RemoveAll(cryptDir)

	pw := []byte("Password1!!")

	err = Initialise(cryptDir, pw, nil)
	require.Nil(t, err)

	filesDir, err := ioutil.TempDir("", "crypt_files")
	require.Nil(t, err)
	defer os.RemoveAll(filesDir)
	fp := filepath.Join(filesDir, "hello_crypt")
	f, err := os.Create(fp)
	require.Nil(t, err)
	_, err = f.Write([]byte("hello crypt!"))
	require.Nil(t, err)

	err = Encrypt([]string{fp, fp + ".crypt"}, cryptDir, pw)
	require.Nil(t, err)

	pwNew := []byte("Password2!!")

	err = Decrypt([]string{fp + ".crypt", fp + ".out"}, cryptDir, pwNew)
	require.ErrorIs(t, err, ErrWrongPassword)

	err = ChangePassword(cryptDir, pw, pwNew)
	require.Nil(t, err)

	err = Decrypt([]string{fp + ".crypt", fp + ".out"}, cryptDir, pw)
	require.ErrorIs(t, err, ErrWrongPassword)
	err = Decrypt([]string{fp + ".crypt", fp + ".out"}, cryptDir, pwNew)
	require.Nil(t, err)

	f, err = os.Open(fp + ".out")
	require.Nil(t, err)
	b, err := ioutil.ReadAll(f)
	require.Nil(t, err)
	require.Equal(t, []byte("hello crypt!"), b)
}
