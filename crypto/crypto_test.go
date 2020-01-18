// Use of this source code is governed by the license that can be found in LICENSE file.
package crypto

import (
	"fmt"
	"testing"
)

func TestGenPWD(t *testing.T) {
	fmt.Println(GenRandString(8))
	fmt.Println(GenPassword(8))
}

func TestEncrypt(t *testing.T) {
	en, err := Encrypt([]byte("xzhang"), []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf("failed to encrypt. Err: %v", err)
	}
	fmt.Printf("en: %s\n", string(en))
	plain, err := Decrypt(en, []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf("failed to decrypt. Err: %v", err)
	}

	fmt.Printf("plaintext: %s\n", plain)
}
func TestEncryptBase64(t *testing.T) {
	en, err := EncryptBase64([]byte("xzhang"), []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf("failed to encrypt. Err: %v", err)
	}
	fmt.Printf("base64: %s\n", string(en))
	plain, err := DecryptBase64(en, []byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf("failed to decrypt. Err: %v", err)
	}

	fmt.Printf("plaintext: %s\n", plain)
}
