package models

type User struct {
	ID                 string `json:"id"`
	MessagingPublicKey []byte `json:"messaging_public_key"` //temporarily replace []byte with string
	AuthPublicKey      []byte `json:"auth_public_key"`      //temporarily replace []byte with string
	Nickname           string `json:"nickname"`
	CreatedAt          string `json:"created_at"`
}
