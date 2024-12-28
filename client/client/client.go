package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
)

const backendURL = "http://localhost:8080"

// RegisterUser registers a new user with the backend
func RegisterUser(userID, messagingPublicKey, authPublicKey, nickname string) error {
	requestBody, err := json.Marshal(map[string]string{
		"id":                   userID,
		"messaging_public_key": messagingPublicKey,
		"auth_public_key":      authPublicKey,
		"nickname":             nickname,
	})
	if err != nil {
		return err
	}

	resp, err := http.Post(backendURL+"/register", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to register user")
	}

	return nil
}

// SendMessage sends an encrypted message to the backend
func SendMessage(senderID, receiverID, encryptedMessage, signature string) error {
	// Create the request payload
	requestBody, err := json.Marshal(map[string]string{
		"sender_id":   senderID,
		"receiver_id": receiverID,
		"message":     encryptedMessage,
		"signature":   signature,
	})
	if err != nil {
		return err
	}

	// Send the request
	resp, err := http.Post(backendURL+"/send", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to send message")
	}

	return nil
}

// GetMessages retrieves messages for a user from the backend
func GetMessages(userID, signature string) ([]map[string]interface{}, error) {
	requestBody, err := json.Marshal(map[string]string{
		"user_id":   userID,
		"signature": signature,
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(backendURL+"/messages", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve messages")
	}

	var result map[string][]map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result["messages"], nil
}
