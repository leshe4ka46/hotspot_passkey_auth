package handlers

import (
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func NoKeysHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "Cookie get err"})
			return
		}
		_, err = database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}

		log.Info().Str("mac:", c.Query("mac")).Msg("")
		if err := database.AddMacRadcheck(c.Query("mac")); err != nil {
			log.Error().Err(err).Msg("")
			// c.JSON(404, gin.H{"error": "DB err"}) // may be duplicate error, ignore
			// return
		}
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
