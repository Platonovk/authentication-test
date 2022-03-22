package main

import (
	"log"
	"net/http"
	"os"
	"time"

	middleware "github.com/Platonovk/authentication-test/middleware"
	routes "github.com/Platonovk/authentication-test/routes"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	_ "github.com/heroku/x/hmetrics/onload"
)

type login struct {
	GUID string `form:"guid" json:"guid" binding:"required"`
}

var SECRET_KEY string = os.Getenv("SECRET_KEY")

type User struct {
	GUID string
}

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	router.Use(gin.Logger())
	routes.UserRoutes(router)

	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Key:     []byte(SECRET_KEY),
		Timeout: 100 * time.Second,

		SendCookie:     true,
		SecureCookie:   false,
		CookieHTTPOnly: true,
		CookieDomain:   "localhost:8000",
		CookieName:     "access_token",
		TokenLookup:    "cookie:access_token",
		CookieSameSite: http.SameSiteDefaultMode,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	errInit := authMiddleware.MiddlewareInit()

	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	router.Use(middleware.Authentication())

	router.Run(":" + port)
}
