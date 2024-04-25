package handlers

import (
	"github.com/gin-gonic/gin"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
)

func LogoutHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user, err := database.GetUserByCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user.Cookies = db.RemoveStr(user.Cookies, cookie)
		database.UpdateUser(user)
		c.SetCookie(consts.LoginCookieName, "", 0, "/", consts.CookieDomain, false, true)
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
