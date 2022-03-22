package controllers

import (
	"context"

	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"

	"github.com/Platonovk/authentication-test/database"

	helper "github.com/Platonovk/authentication-test/helpers"
	"github.com/Platonovk/authentication-test/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func CreateUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		user.ID = primitive.NewObjectID()
		user.GUID = user.ID.Hex()
		accessToken, refreshTokenPlain, refreshTokenEncrypted, _ := helper.GenerateAllTokens(user.GUID)
		user.Access_token = &accessToken
		user.Refresh_token = &refreshTokenEncrypted

		userCollection.InsertOne(ctx, user)
		defer cancel()

		c.JSON(http.StatusOK, gin.H{
			"GUID":                    user.GUID,
			"refresh_token":           refreshTokenPlain,
			"refresh_token_encrypted": refreshTokenEncrypted,
		})

	}
}

func ReturnTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var foundUser models.User

		inputGUID := c.Query("guid")

		err := userCollection.FindOne(ctx, bson.M{"guid": inputGUID}).Decode(&foundUser)

		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "GUID is incorrect",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access token":            foundUser.Access_token,
			"encrypted refresh token": foundUser.Refresh_token,
		})
	}
}

func Refresh() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var foundUser models.User

		inGUID := c.Query("guid")
		err := userCollection.FindOne(ctx, bson.M{"guid": inGUID}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid GUID"})
			return
		}

		inRefreshEncrypted, err := bcrypt.GenerateFromPassword([]byte(c.Request.Header.Get("refresh_token")), 1)

		if string(*foundUser.Refresh_token) != string(inRefreshEncrypted) {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":      "Invalid refresh token",
				"refreshIn":  inRefreshEncrypted,
				"refreshReq": *foundUser.Refresh_token,
			})
			return
		}

		accessToken, refreshTokenPlain, refreshTokenEncrypted, _ := helper.GenerateAllTokens(foundUser.GUID)

		helper.UpdateAllTokens(accessToken, refreshTokenEncrypted, foundUser.GUID)

		c.JSON(http.StatusOK, gin.H{
			"GUID":              foundUser.GUID,
			"new refresh token": refreshTokenPlain,
		})
	}
}
