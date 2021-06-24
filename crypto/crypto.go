// Use of this source code is governed by the license that can be found in LICENSE file.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

/*func foo() {
	a := ""
	var b []byte
	_, err := base64.StdEncoding.Decode([]byte(a), b)
    if err != nil {
        log.Fatal(err)
    }

	var out bytes.Buffer
    p := pem.EncodeToMemory(pem.Block{Type: "CERTIFICATE", Bytes: b})

}*/

// HashPassword hmac password and encodes it as base64.
func HashPassword(pwd, pepper string) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(pwd))
	pwdDigest := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	pwdDigest = strings.TrimRight(pwdDigest, "=")
	return bcrypt.GenerateFromPassword([]byte(pwdDigest), 12)
}

// CompareWithHashedPassword encodes the given pwd and compares it with the hashed one.
func CompareWithHashedPassword(pwd, hashed, pepper string) bool {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(pwd))
	pwdDigest := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	pwdDigest = strings.TrimRight(pwdDigest, "=")
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(pwdDigest))
	return err == nil
}

// SHA1FromByte returns base64 encoded SHA1 from the given bytes.
func SHA1FromByte(b []byte) string {
	sum := sha1.Sum(b)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(sum[:]), "=")
}

// SHA1FromFile returns a base64 encoded SHA1 from the given file.
func SHA1FromFile(pth string) (string, error) {
	f, err := ioutil.ReadFile(pth)
	if err != nil {
		return "", err
	}

	return SHA1FromByte(f), nil
}

// MD5FromByte returns a base64 encoded MD5 from the given bytes.
func MD5FromByte(b []byte) string {
	sum := md5.Sum(b)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(sum[:]), "=")
}

// MD5FromFile returns a base64 encoded MD5 from the given file.
func MD5FromFile(pth string) (string, error) {
	f, err := ioutil.ReadFile(pth)
	if err != nil {
		return "", err
	}

	return MD5FromByte(f), nil
}

var randSource = mathrand.NewSource(time.Now().UnixNano())

const (
	// used for generating passwords
	letterBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]`~"
	// used for generated a filename or an id
	letter64      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	alphanumeric  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alphabet      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	letterIdxBits = 7
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

// GenRandString generates a string starting a alphabet letter and ending with alphanumberica letter.
// abc2-Cd2
// This function can be used to generate a file name, username, file id etc.
// The collission should be very small if n >= 8
func GenRandString(n int) string {
	if n <= 2 {
		return genRandString(n, alphanumeric)
	}

	return genRandString(1, alphabet) + genRandString(n-2, letter64) + genRandString(1, alphanumeric)
}

// GenPassword generates a password of length n.
func GenPassword(n int) string {
	return genRandString(n, letterBytes)
}

// GenPasswordLetter62 generates a string using alphanumeric.
func GenPasswordLetter62(n int) string {
	return genRandString(n, alphanumeric)
}

func genRandString(n int, charSet string) string {
	b := make([]byte, n)
	// A randSource.Int63() generates 63 random bits,
	// enough for letterIdxMax characters!
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(charSet) {
			b[i] = charSet[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// CreateTLSConfig creates a tls.Config from the specified cert files.
func CreateTLSConfig(certFile, keyFile, caFile string, insecure bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	t := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: insecure,
	}

	return t, nil
}

// Encrypt symetrically encrpts a plaintext.
// NewCipher creates and returns a new cipher.Block. The key argument
// should be the AES key, either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// https://stackoverflow.com/questions/47382035/unable-to-decrypt-after-aes-gcm-base64-in-go
// Problem without base64 encoding: "cipher: message authentication failed"
// This error occurs when decrypting the encrypted text which was written to a file.
func EncryptBase64(plaintext, key []byte) ([]byte, error) {
	cipher, err := Encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}

	base64Cipher := make([]byte, base64.RawStdEncoding.EncodedLen(len(cipher)))
	base64.RawStdEncoding.Encode(base64Cipher, cipher)

	return base64Cipher, nil
}

// Decrypt decrypts a salted string.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DecryptBase64 decrypts a salted base64 string.
func DecryptBase64(base64Cipher, key []byte) ([]byte, error) {
	cipher := make([]byte, base64.RawStdEncoding.DecodedLen(len(base64Cipher)))
	_, err := base64.RawStdEncoding.Decode(cipher, base64Cipher)
	if err != nil {
		return nil, err
	}
	return Decrypt(cipher, key)
}
