package models

type Message struct {
	ID               int    `json:"id"`
	SenderID         string `json:"sender_id"`
	ReceiverID       string `json:"receiver_id"`
	EncryptedMessage []byte `json:"message"` //temporarily replace []byte with string
	Timestamp        string `json:"timestamp"`
}

type MessageRequest struct {
	SenderID         string `json:"sender_id"`
	ReceiverID       string `json:"receiver_id"`
	EncryptedMessage []byte `json:"message"`
	Signature        string `json:"signature"` // Signature of the request
}

type GetMessagesRequest struct {
	UserID    string `json:"user_id"`
	Signature string `json:"signature"` // Signature of the request
}
