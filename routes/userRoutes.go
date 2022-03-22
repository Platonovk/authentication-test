package rotues

import (
	controller "github.com/Platonovk/authentication-test/controllers"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/createuser", controller.CreateUser())
	incomingRoutes.POST("/route1", controller.ReturnTokens())
	incomingRoutes.POST("/route2", controller.Refresh())
}
