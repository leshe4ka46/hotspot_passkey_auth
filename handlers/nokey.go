package handlers

import (
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"github.com/gin-gonic/gin"
)

func NoKeysHandler(database *db.DB) gin.HandlerFunc {
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
		database.AddMacRadcheck(db.GetMacByCookie(db_user.Mac,db_user.Cookies,cookie))
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
