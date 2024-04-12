package handlers

import (
	_ "encoding/base64"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
)

func InfoHandler(database *gorm.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user, err := db.GetUserByCookie(database, cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		c.JSON(200, gin.H{"status": "OK", "data":gin.H{"username":user.Username}})
	}
	return gin.HandlerFunc(fn)
}
