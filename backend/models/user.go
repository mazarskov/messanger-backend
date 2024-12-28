package models

type User struct {
	ID                 string `json:"id"`
	MessagingPublicKey string `json:"messaging_public_key"` //temporarily replace []byte with string
	AuthPublicKey      string `json:"auth_public_key"`      //temporarily replace []byte with string
	Nickname           string `json:"nickname"`
	CreatedAt          string `json:"created_at"`
}
