package handlers

import (
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"

	"github.com/gin-gonic/gin"
)

func AdminHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "Cookie get err"})
			return
		}
		db_user, err := database.GetUserByCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		if !db_user.IsAdmin {
			c.JSON(404, gin.H{"error": "Not an admin"})
			return
		}
		res, err := database.GetRadcheck()
		if err != nil {
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		c.JSON(200, gin.H{"status": "OK", "data": res})
	}
	return gin.HandlerFunc(fn)
}
