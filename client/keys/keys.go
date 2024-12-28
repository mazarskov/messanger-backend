package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

// GenerateKeyPair generates a new RSA key pair
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// SignRequest signs a request using the private key
func SignRequest(privateKey *rsa.PrivateKey, senderID, receiverID string, encryptedMessage []byte) (string, error) {
	// Create the message to sign
	message := map[string]interface{}{
		"sender_id":         senderID,
		"receiver_id":       receiverID,
		"encrypted_message": encryptedMessage,
	}
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	// Hash the message
	hash := sha256.Sum256(messageBytes)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	// Encode the signature as Base64
	return base64.StdEncoding.EncodeToString(signature), nil
}

// SaveKeyToFile saves a key to a file
func SaveKeyToFile(key interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var pemBlock *pem.Block
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *rsa.PublicKey:
		bytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return err
		}
		pemBlock = &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: bytes,
		}
	default:
		return errors.New("unsupported key type")
	}

	return pem.Encode(file, pemBlock)
}

// EncryptMessage encrypts a message using the recipient's public key
func EncryptMessage(publicKey *rsa.PublicKey, message []byte) ([]byte, error) {
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		return nil, err
	}
	return encryptedBytes, nil
}

// DecryptMessage decrypts a message using the recipient's private key
func DecryptMessage(privateKey *rsa.PrivateKey, encryptedMessage []byte) ([]byte, error) {
	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedMessage)
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

// LoadPrivateKeyFromFile loads a private key from a PEM file
func LoadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadPublicKeyFromFile loads a public key from a PEM file
func LoadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

// GenerateSignature generates a signature for a message
func GenerateSignature(privateKey *rsa.PrivateKey, senderID, receiverID, message string) (string, error) {
	// Create the message to sign
	messageToSign := map[string]string{
		"sender_id":   senderID,
		"receiver_id": receiverID,
		"message":     message,
	}
	messageBytes, err := json.Marshal(messageToSign)
	if err != nil {
		return "", err
	}

	// Hash the message
	hash := sha256.Sum256(messageBytes)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	// Encode the signature as Base64
	return base64.StdEncoding.EncodeToString(signature), nil
}
