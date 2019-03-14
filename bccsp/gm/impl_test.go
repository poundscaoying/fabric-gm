/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"bytes"
	"fmt"
	"hash"
	"math/big"
	"os"
	"testing"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/hyperledger/gmsm/sm3"
	"time"
	"net"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	currentKS         bccsp.KeyStore
	currentBCCSP      bccsp.BCCSP
	currentTestConfig testConfig
)

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
)

type testConfig struct {
	securityLevel int
	hashFamily    string
}

func TestMain(m *testing.M) {
	ks, err := NewFileBasedKeyStore(nil, os.TempDir(), false)
	if err != nil {
		fmt.Printf("Failed initiliazing KeyStore [%s]", err)
		os.Exit(-1)
	}
	currentKS = ks

	tests := []testConfig{
		{256, "SM3"},
	}

	for _, config := range tests {
		var err error
		currentTestConfig = config
		currentBCCSP, err = New(config.securityLevel, config.hashFamily, currentKS)
		if err != nil {
			fmt.Printf("Failed initiliazing BCCSP at [%d, %s]: [%s]", config.securityLevel, config.hashFamily, err)
			os.Exit(-1)
		}
		ret := m.Run()
		if ret != 0 {
			fmt.Printf("Failed testing at [%d, %s]", config.securityLevel, config.hashFamily)
			os.Exit(-1)
		}
	}
	os.Exit(0)
}







//KEYGEN
func TestKeyGenGMSM2Opts(t *testing.T) {
	// Curve P256
	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA P256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA P256 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA P256 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA P256 key. Key should be asymmetric")
	}

	gmsm2Key := k.(*gmsm2PrivateKey).privKey
	if !sm2.P256Sm2().IsOnCurve(gmsm2Key.X, gmsm2Key.Y) {
		t.Fatal("P256 generated key in invalid. The public key must be on the P256 curve.")
	}

	if gmsm2Key.D.Cmp(big.NewInt(0)) == 0 {
		t.Fatal("P256 generated key in invalid. Private key must be different from 0.")
	}


}

func TestGMSM2KeyGenEphemeral(t *testing.T) {
	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
	raw, err := k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Public key must be different from nil.")
	}
}

func TestKeyGenGMSM4Opts(t *testing.T) {
	// GMSM4 128
	k, err := currentBCCSP.KeyGen(&bccsp.GMSM4KeyGenOpts{Temporary: false})
	fmt.Println(k)
	if err != nil {
		t.Fatalf("Failed generating GMSM4 128 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating AES 128 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating AES 128 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating AES 128 key. Key should be symmetric")
	}


}

//GMSM2 BCCSPKEY
func TestGMSM2PrivateKeySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	ski := k.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestGMSM2KeyGenNonEphemeral(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating ECDSA key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
}

func TestGMSM2PublicKeyFromPrivateKey(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed getting public key from private ECDSA key. Key must be different from nil")
	}
	if pk.Private() {
		t.Fatal("Failed generating ECDSA key. Key should be public")
	}
	if pk.Symmetric() {
		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
	}
}

func TestGMSM2PublicKeyBytes(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	raw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling ECDSA public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling ECDSA public key. Zero length")
	}
}

func TestGMSM2PublicKeySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	ski := pk.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}



//KEYIMPORT

func TestGMSM2KeyImportFromGMSM2PublicKey(t *testing.T) {

	// Generate an ECDSA key
	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}

	////pub, err := utils.DERToPublicKey(pkRaw)
	//pub, err := sm2.ParseSm2PublicKey(pkRaw)
	//if err != nil {
	//	t.Fatalf("Failed converting raw to ecdsa.PublicKey [%s]", err)
	//}

	// Import the ecdsa.PublicKey
	pk2, err := currentBCCSP.KeyImport(pkRaw, &bccsp.GMSM2PublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

func TestGMSM2KeyImportFromGMSM2PrivateKey(t *testing.T) {

	// Generate an ECDSA key, default is P256
	//key, err := ecdsa.GenerateKey(sm2.P256Sm2(), rand.Reader)
	key, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Import the ecdsa.PrivateKey
	//priv, err := utils.PrivateKeyToDER(key)
	priv, err := sm2.MarshalSm2PrivateKey(key,nil)

	if err != nil {
		t.Fatalf("Failed converting raw to ecdsa.PrivateKey [%s]", err)
	}

	sk, err := currentBCCSP.KeyImport(priv, &bccsp.GMSM2PrivateKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing ECDSA private key [%s]", err)
	}
	if sk == nil {
		t.Fatal("Failed importing ECDSA private key. Return BCCSP key cannot be nil.")
	}

	// Import the ecdsa.PublicKey
	//pub, err := utils.PublicKeyToDER(&key.PublicKey)
	pub, err := sm2.MarshalSm2PublicKey(&key.PublicKey)

	if err != nil {
		t.Fatalf("Failed converting raw to ecdsa.PublicKey [%s]", err)
	}

	pk, err := currentBCCSP.KeyImport(pub, &bccsp.GMSM2PublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(sk, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}


func TestKeyImportFromX509GMSM2PublicKey(t *testing.T) {


	// Generate a self-signed certificate
	testExtKeyUsage := []sm2.ExtKeyUsage{sm2.ExtKeyUsageClientAuth, sm2.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := sm2.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: sm2.SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     sm2.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA: true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}

	priv, err := sm2.GenerateKey() // 生成密钥对

	pubKey, _ := priv.Public().(*sm2.PublicKey)
	ok, _ := sm2.CreateCertificateToPem("cert.pem", &template, &template, pubKey, priv)
	if ok != true {
		fmt.Printf("failed to create cert file\n")
	}
	cert, err := sm2.ReadCertificateFromPem("cert.pem")
	if err != nil {
		fmt.Printf("failed to read cert file")
	}
	//fmt.Println("cert:",cert)
	// Import the certificate's public key
	pk2, err := currentBCCSP.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}
	//
	//fmt.Println("k:",k)
	//fmt.Println("priv:",priv)

	sign, err := priv.Sign(rand.Reader, digest, nil) // 签名
	if err != nil {
		t.Fatalf("Failed Sign [%s]", err)
	}
	ok = pubKey.Verify(digest, sign) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
}



//GETKEY
func TestInvalidSKI(t *testing.T) {
	k, err := currentBCCSP.GetKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	k, err = currentBCCSP.GetKey([]byte{0, 1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestGMSM2GetKeyBySKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	k2, err := currentBCCSP.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting ECDSA key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting ECDSA key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting ECDSA key. Key should be private")
	}
	if k2.Symmetric() {
		t.Fatal("Failed getting ECDSA key. Key should be asymmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

func TestGMSM4KeyGenSKI(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	k2, err := currentBCCSP.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting AES_256 key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting AES_256 key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting AES_256 key. Key should be private")
	}
	if !k2.Symmetric() {
		t.Fatal("Failed getting AES_256 key. Key should be symmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}

}

//HASH
func TestGMSM3(t *testing.T) {

	for i := 0; i < 100; i++ {
		b, err := GetRandomBytes(i)
		if err != nil {
			t.Fatalf("Failed getting random bytes [%s]", err)
		}

		h1, err := currentBCCSP.Hash(b, &bccsp.GMSM3Opts{})
		if err != nil {
			t.Fatalf("Failed computing SHA [%s]", err)
		}

		var h hash.Hash
		//switch currentTestConfig.hashFamily {
		//case "SHA2":
		//	switch currentTestConfig.securityLevel {
		//	case 256:
		//		h = sha256.New()
		//	case 384:
		//		h = sha512.New384()
		//	default:
		//		t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
		//	}
		//case "SHA3":
		//	switch currentTestConfig.securityLevel {
		//	case 256:
		//		h = sha3.New256()
		//	case 384:
		//		h = sha3.New384()
		//	default:
		//		t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
		//	}
		//default:
		//	t.Fatalf("Invalid hash family [%s]", currentTestConfig.hashFamily)
		//}

		h=sm3.New()
		h.Write(b)
		h2 := h.Sum(nil)
		if !bytes.Equal(h1, h2) {
			t.Fatalf("Discrempancy found in HASH result [%x], [%x]!=[%x]", b, h1, h2)
		}
	}
}

//GETHASH
//no need for gethash function

//SIGN
func TestGMSM2Sign(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.SHAOpts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}
}

//VERIFY
func TestGMSM2Verify(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := currentBCCSP.Hash(msg, &bccsp.GMSM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := currentBCCSP.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := currentBCCSP.Verify(k, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}

	valid, err = currentBCCSP.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

	// Store public key
	err = currentKS.StoreKey(pk)
	if err != nil {
		t.Fatalf("Failed storing corresponding public key [%s]", err)
	}

	pk2, err := currentKS.GetKey(pk.SKI())
	if err != nil {
		t.Fatalf("Failed retrieving corresponding public key [%s]", err)
	}

	valid, err = currentBCCSP.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

//ENCRYPT
func TestGMSM4Encrypt(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}
	fmt.Println(k)

	ct, err := currentBCCSP.Encrypt(k, []byte("hello world"), &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed encrypting. Nil ciphertext")
	}
}

//DECRYPT
func TestGMSM4Decrypt(t *testing.T) {

	k, err := currentBCCSP.KeyGen(&bccsp.GMSM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating AES_256 key [%s]", err)
	}

	msg := []byte("hello world")

	ct, err := currentBCCSP.Encrypt(k, msg, &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := currentBCCSP.Decrypt(k, ct, bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}