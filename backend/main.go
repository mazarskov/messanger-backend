package main

import (
	"messanger/backend/database"
	"messanger/backend/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize the database
	database.InitDB()
	defer database.DB.Close()

	// Create a Gin router
	router := gin.Default()

	// Define routes
	router.POST("/register", func(c *gin.Context) {
		handlers.RegisterUser(c, database.DB)
	})
	router.POST("/send", func(c *gin.Context) {
		handlers.SendMessage(c, database.DB)
	})
	router.GET("/messages", func(c *gin.Context) {
		handlers.GetMessages(c, database.DB)
	})

	// Start the server
	router.Run(":8080")
}
