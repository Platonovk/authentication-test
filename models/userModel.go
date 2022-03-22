package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID            primitive.ObjectID `bson:"_id"`
	Access_token  *string            `json:"access_token"`
	Refresh_token *[]byte            `json:"refresh_token"`
	GUID          string             `json:"guid"`
}
