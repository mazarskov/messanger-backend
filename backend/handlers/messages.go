package handlers

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"

	"messanger/backend/models"

	"github.com/gin-gonic/gin"
)

func SendMessage(c *gin.Context, db *sql.DB) {
	var req models.MessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Received send request: SenderID=%s, ReceiverID=%s, EncryptedMessage=%s, Signature=%s",
		req.SenderID, req.ReceiverID, req.EncryptedMessage, req.Signature)

	// Retrieve the sender's public key
	var authPublicKeyBytes []byte
	err := db.QueryRow("SELECT auth_public_key FROM users WHERE id = ?", req.SenderID).Scan(&authPublicKeyBytes)
	if err != nil {
		log.Printf("Failed to retrieve sender's public key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sender not found"})
		return
	}

	log.Printf("Sender's public key (raw): %s", string(authPublicKeyBytes))

	// Decode the Base64-encoded public key (if necessary)
	decodedKey, err := base64.StdEncoding.DecodeString(string(authPublicKeyBytes))
	if err != nil {
		log.Printf("Failed to decode public key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode public key"})
		return
	}

	log.Printf("Decoded public key: %x", decodedKey)

	// Convert the raw key to PEM format
	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY", // Use "PUBLIC KEY" for PKCS#8
		Bytes: decodedKey,
	}
	pemKey := pem.EncodeToMemory(pemBlock)
	log.Printf("PEM-encoded public key: %s", string(pemKey))

	// Parse the public key
	block, _ := pem.Decode(pemKey)
	if block == nil {
		log.Printf("Failed to decode PEM block containing public key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid public key format"})
		return
	}

	var pubKey interface{}
	_ = pubKey
	if block.Type == "RSA PUBLIC KEY" {
		// PKCS#1 format
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			log.Printf("Failed to parse PKCS#1 public key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse public key"})
			return
		}
	} else if block.Type == "PUBLIC KEY" {
		// PKCS#8 format
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("Failed to parse PKIX public key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse public key"})
			return
		}
	} else {
		log.Printf("Unsupported public key type: %s", block.Type)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unsupported public key format"})
		return
	}

	// Verify the signature
	// if err := verifySignature(pubKey.(*rsa.PublicKey), req.SenderID, req.ReceiverID, req.EncryptedMessage, req.Signature); err != nil {
	// 	log.Printf("Failed to verify signature: %v", err)
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
	// 	return
	// }

	// Insert message into the database
	_, err = db.Exec("INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
		req.SenderID, req.ReceiverID, req.EncryptedMessage)
	if err != nil {
		log.Printf("Failed to insert message into database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send message"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "message sent"})
}

func GetMessages(c *gin.Context, db *sql.DB) {
	log.Printf("Started getmessage")
	var req models.GetMessagesRequest
	// if err := c.ShouldBindJSON(&req); err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	// 	return
	// }
	log.Printf("Started retrieving public key")
	// Retrieve the user's public key

	var authPublicKeyBytes []byte
	log.Printf("Started user id=%s", req.UserID)
	err := db.QueryRow("SELECT auth_public_key FROM users WHERE id = 'bob'", req.UserID).Scan(&authPublicKeyBytes) //hardcoded bob
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	// DISABLED THOSE TWO FOR TESTING
	// Parse the public key
	// authPublicKey, err := x509.ParsePKCS1PublicKey(authPublicKeyBytes)
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse public key"})
	// 	return
	// }

	// // Verify the signature
	// if err := verifySignature(authPublicKey, req.UserID, "", nil, req.Signature); err != nil {
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
	// 	return
	// }

	// Retrieve messages for the user
	rows, err := db.Query("SELECT id, sender_id, message, timestamp FROM messages WHERE receiver_id = 'bob'", req.UserID) //hardcoded bob
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve messages"})
		return
	}
	defer rows.Close()

	var messages []models.Message
	for rows.Next() {
		var message models.Message
		if err := rows.Scan(&message.ID, &message.SenderID, &message.EncryptedMessage, &message.Timestamp); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read message"})
			return
		}
		messages = append(messages, message)
	}

	c.JSON(http.StatusOK, gin.H{"messages": messages})
}

func verifySignature(publicKey *rsa.PublicKey, senderID, receiverID string, encryptedMessage []byte, signature string) error {
	log.Printf("Started creating message to verify")
	// Create the message to verify
	message := map[string]interface{}{
		"sender_id":   senderID,
		"receiver_id": receiverID,
		"message":     encryptedMessage,
	}
	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return err
	}
	log.Printf("Message to verify: %s", string(messageBytes))

	log.Printf("Started hashing the message")
	// Hash the message
	hash := sha256.Sum256(messageBytes)
	log.Printf("Message hash: %x", hash)

	log.Printf("Started decoding the signature")
	// Decode the signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Printf("Failed to decode signature: %v", err)
		return err
	}
	log.Printf("Decoded signature: %x", signatureBytes)

	log.Printf("Started final verification")
	// Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signatureBytes)
	if err != nil {
		log.Printf("Failed to verify signature: %v", err)
		return err
	}

	log.Printf("Signature verified successfully")
	return nil
}
