package handlers

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"math/rand"
	"time"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func makeNewUser(database *db.DB,c *gin.Context) {
	uid := base64.RawStdEncoding.EncodeToString(uuid.NewV4().Bytes())
	c.SetCookie(consts.LoginCookieName, uid, consts.CookieLifeTime, "/", consts.CookieDomain, consts.SecureCookie, true)
	database.AddUser(&db.Gocheck{Cookies: uid, Username: RandStringRunes(64)})
}

func InfoHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil || cookie == "" {
			makeNewUser(database,c)
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user, err := database.GetUserByCookie(cookie)
		if err != nil || user.Password == "" {
			makeNewUser(database,c)
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		c.JSON(200, gin.H{"status": "OK", "data": gin.H{"username": user.Username}})
	}
	return gin.HandlerFunc(fn)
}
