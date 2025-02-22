package handlers

import (
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func makeNewUser(database *db.DB, c *gin.Context) {
	uid := utils.NewUUIDV4()
	cookie := utils.RandStringRunes(64)
	c.SetCookie(consts.LoginCookieName, cookie, consts.CookieLifeTime, "/", consts.CookieDomain, consts.SecureCookie, true)
	if err := database.AddUser(&db.Gocheck{Cookies: []db.CookieData{{Cookie: cookie}}, Username: uid, Id: uid}); err != nil {
		log.Error().Err(err).Msg("")
		c.JSON(500, utils.EncodeError(gin.H{"error": "DB err"}))
		return
	}
}

func InfoHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			makeNewUser(database, c)
			c.JSON(500, utils.EncodeError(gin.H{"error": "Cookie not found"}))
			return
		}
		user, err := database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			makeNewUser(database, c)
			c.JSON(500, utils.EncodeError(gin.H{"error": "User not found (not valid cookie)"}))
			return
		}

		if user.Password == "" {
			c.JSON(500, utils.EncodeError(gin.H{"error": "User not found"}))
			return
		}

		c.JSON(200, utils.EncodeSuccess(gin.H{"username": user.Username, "admin": user.IsAdmin}))
	}
	return gin.HandlerFunc(fn)
}
