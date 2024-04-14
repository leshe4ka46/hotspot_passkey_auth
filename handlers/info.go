package handlers

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
	"gorm.io/gorm"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/store"
)

func InfoHandler(database *gorm.DB, userProvider *store.SessionProvider) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil || cookie=="" {
			uid := base64.RawStdEncoding.EncodeToString(uuid.NewV4().Bytes())
			c.SetCookie(consts.LoginCookieName, uid, consts.CookieLifeTime, "/", consts.CookieDomain, false, true)
			userProvider.Set(&store.UserSession{Cookie: uid})
			db.AddUser(database, &db.Gocheck{Cookies: uid})
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user, err := db.GetUserByCookie(database, cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		c.JSON(200, gin.H{"status": "OK", "data": gin.H{"username": user.Username}})
	}
	return gin.HandlerFunc(fn)
}
