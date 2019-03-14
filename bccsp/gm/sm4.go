/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm4"
	"crypto/cipher"
	"bytes"
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func SM4Encrypt(key, src []byte) ([]byte, error) {
	// // First pad
	// tmp := pkcs7Padding(src)

	// // Then encrypt
	// return aesCBCEncrypt(key, tmp)
	dst := make([]byte, len(src))
	sm4.EncryptBlock(key, dst, src)
	return dst, nil
}

// AESCBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func SM4Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	// pt, err := aesCBCDecrypt(key, src)
	// if err == nil {
	// 	return pkcs7UnPadding(pt)
	// }

	dst := make([]byte, len(src))
	sm4.DecryptBlock(key, dst, src)
	return dst, nil
}
//test
func Sm4Encryption(key,  plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData := pkcs7Padding(plainText)
	blockMode := cipher.NewCBCEncrypter(block, key)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func Sm4Decryption(key,cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData,_ = pkcs7UnPadding(origData)
	return origData, nil
}

func pkcs7Padding(src []byte) []byte {
	padding := sm4.BlockSize - len(src)%sm4.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > sm4.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

//*test
type gmsm4Encryptor struct{}

//实现 Encryptor 接口
func (*gmsm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {

	return Sm4Encryption(k.(*gmsm4PrivateKey).privKey, plaintext)
	//return AESCBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)

	// key := k.(*gmsm4PrivateKey).privKey
	// var en = make([]byte, 16)
	// sms4(plaintext, 16, key, en, 1)
	// return en, nil
}

type gmsm4Decryptor struct{}

//实现 Decryptor 接口
func (*gmsm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {

	return Sm4Decryption(k.(*gmsm4PrivateKey).privKey, ciphertext)
	// var dc = make([]byte, 16)
	// key := k.(*gmsm4PrivateKey).privKey
	// sms4(ciphertext, 16, key, dc, 0)
	// return dc, nil
}
