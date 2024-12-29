package database

import (
	"database/sql"
	"log"

	"messanger/backend/models"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./messanger.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create tables
	createTables()
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            messaging_public_key BLOB NOT NULL,
            auth_public_key BLOB NOT NULL,
            nickname TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            message BLOB NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );`,
	}

	for _, query := range queries {
		_, err := DB.Exec(query)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func FetchAllItems(db *sql.DB) ([]models.User, error) {
	// Prepare the query
	query := "SELECT * FROM users;"

	// Execute the query
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Iterate through the rows and map to the struct
	var users []models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.MessagingPublicKey, &user.AuthPublicKey, &user.Nickname, &user.CreatedAt); err != nil {
			log.Printf("Error during rows.Scan: %v", err)
			return nil, err
		}
		log.Printf("Fetched user with ID %s", user.ID)
		users = append(users, user)
	}
	// Check for errors from iteration
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
