package handlers

import (
	"database/sql"
	"log"
	"net/http"

	"messanger/backend/database"
	"messanger/backend/models"

	"github.com/gin-gonic/gin"
)

func RegisterUser(c *gin.Context, db *sql.DB) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Insert user into the database
	log.Printf("Started adding to db")
	_, err := db.Exec("INSERT INTO users (id, messaging_public_key, auth_public_key, nickname) VALUES (?, ?, ?, ?)",
		user.ID, user.MessagingPublicKey, user.AuthPublicKey, user.Nickname)
	log.Printf("Added id=%s", user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "user registered"})
}

func GetUsers(c *gin.Context, db *sql.DB) {
	var users, err = database.FetchAllItems(database.DB)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}
