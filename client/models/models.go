package models

import "crypto/rsa"

type User struct {
	ID                  string          `json:"id"`
	MessagingPublicKey  string          `json:"messaging_public_key"`
	AuthPublicKey       string          `json:"auth_public_key"`
	Nickname            string          `json:"nickname"`
	MessagingPrivateKey *rsa.PrivateKey `json:"-"` // Private key (not serialized)
	AuthPrivateKey      *rsa.PrivateKey `json:"-"` // Private key (not serialized)
}
type MessageRequest struct {
	SenderID         string `json:"sender_id"`
	ReceiverID       string `json:"receiver_id"`
	EncryptedMessage []byte `json:"encrypted_message"`
	Signature        string `json:"signature"`
}

type GetMessagesRequest struct {
	UserID    string `json:"user_id"`
	Signature string `json:"signature"`
}
