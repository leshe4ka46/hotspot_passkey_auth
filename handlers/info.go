package handlers

import (
	"encoding/base64"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"math/rand"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/twinj/uuid"
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

func makeNewUser(database *db.DB, c *gin.Context) {
	uid := base64.RawStdEncoding.EncodeToString(uuid.NewV4().Bytes())
	c.SetCookie(consts.LoginCookieName, uid, consts.CookieLifeTime, "/", consts.CookieDomain, consts.SecureCookie, true)
	if err := database.AddUser(&db.Gocheck{Cookies: []db.CookieData{{Cookie: uid}}, Username: RandStringRunes(64)}); err != nil {
		log.Error().Err(err).Msg("")
		c.JSON(404, gin.H{"error": "DB err"})
		return
	}
}

func InfoHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			makeNewUser(database, c)
			c.JSON(404, gin.H{"error": "Cookie not found"})
			return
		}
		user, err := database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			makeNewUser(database, c)
			c.JSON(404, gin.H{"error": "User not found (not valid cookie)"})
			return
		}

		if user.Password == "" {
			c.JSON(404, gin.H{"error": "User have valid cookie, but TRIAL user"})
			return
		}
		c.JSON(200, gin.H{"status": "OK", "data": gin.H{"username": user.Username}})
	}
	return gin.HandlerFunc(fn)
}
