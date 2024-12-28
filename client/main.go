package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"crypto/x509"
	"messanger/client/client"
	"messanger/client/keys"
	"messanger/client/models"
)

var (
	users = make(map[string]*models.User) // In-memory user store
)

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/send", sendHandler)
	http.HandleFunc("/messages", messagesHandler)

	fmt.Println("Client running on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate keys
	messagingPrivateKey, messagingPublicKey, err := keys.GenerateKeyPair()
	if err != nil {
		http.Error(w, "Failed to generate messaging keys", http.StatusInternalServerError)
		return
	}
	authPrivateKey, authPublicKey, err := keys.GenerateKeyPair()
	if err != nil {
		http.Error(w, "Failed to generate authentication keys", http.StatusInternalServerError)
		return
	}

	// Save keys to in-memory store
	users[req.ID] = &models.User{
		ID:                  req.ID,
		MessagingPublicKey:  base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(messagingPublicKey)),
		AuthPublicKey:       base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(authPublicKey)),
		Nickname:            req.Nickname,
		MessagingPrivateKey: messagingPrivateKey,
		AuthPrivateKey:      authPrivateKey,
	}

	// Register with the backend
	if err := client.RegisterUser(req.ID, users[req.ID].MessagingPublicKey, users[req.ID].AuthPublicKey, req.Nickname); err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User %s registered successfully!", req.ID)
}

func sendHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SenderID   string `json:"sender_id"`
		ReceiverID string `json:"receiver_id"`
		Message    string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get sender's authentication private key
	sender, ok := users[req.SenderID]
	if !ok {
		http.Error(w, "Sender not found", http.StatusNotFound)
		return
	}

	// Get receiver's messaging public key
	receiver, ok := users[req.ReceiverID]
	if !ok {
		http.Error(w, "Receiver not found", http.StatusNotFound)
		return
	}
	receiverMessagingPublicKey, err := base64.StdEncoding.DecodeString(receiver.MessagingPublicKey)
	if err != nil {
		http.Error(w, "Failed to decode receiver's public key", http.StatusInternalServerError)
		return
	}
	pubKey, err := x509.ParsePKCS1PublicKey(receiverMessagingPublicKey)
	if err != nil {
		http.Error(w, "Failed to parse receiver's public key", http.StatusInternalServerError)
		return
	}

	// Encrypt the message
	encryptedMessage, err := keys.EncryptMessage(pubKey, []byte(req.Message))
	if err != nil {
		http.Error(w, "Failed to encrypt message", http.StatusInternalServerError)
		return
	}

	// Sign the request
	signature, err := keys.GenerateSignature(sender.AuthPrivateKey, req.SenderID, req.ReceiverID, req.Message)
	if err != nil {
		http.Error(w, "Failed to sign request", http.StatusInternalServerError)
		return
	}

	// Send the message to the backend
	if err := client.SendMessage(req.SenderID, req.ReceiverID, base64.StdEncoding.EncodeToString(encryptedMessage), signature); err != nil {
		http.Error(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Message sent successfully!")
}

func messagesHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user's authentication private key
	user, ok := users[req.UserID]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Sign the request
	signature, err := keys.GenerateSignature(user.AuthPrivateKey, req.UserID, "", "")
	if err != nil {
		http.Error(w, "Failed to sign request", http.StatusInternalServerError)
		return
	}

	// Retrieve messages
	messages, err := client.GetMessages(req.UserID, signature)
	if err != nil {
		http.Error(w, "Failed to retrieve messages", http.StatusInternalServerError)
		return
	}

	// Decrypt each message
	var decryptedMessages []string
	for _, msg := range messages {
		encryptedMessage, err := base64.StdEncoding.DecodeString(msg["encrypted_message"].(string))
		if err != nil {
			http.Error(w, "Failed to decode encrypted message", http.StatusInternalServerError)
			return
		}

		decryptedMessage, err := keys.DecryptMessage(user.MessagingPrivateKey, encryptedMessage)
		if err != nil {
			http.Error(w, "Failed to decrypt message", http.StatusInternalServerError)
			return
		}

		decryptedMessages = append(decryptedMessages, string(decryptedMessage))
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(decryptedMessages)
}
