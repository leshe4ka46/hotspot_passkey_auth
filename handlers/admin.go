package handlers

import (
	"fmt"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func AdminHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "Cookie get err"}))
			return
		}
		db_user, err := database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "DB err"}))
			return
		}
		fmt.Printf("%+v\n", db_user)
		if !db_user.IsAdmin {
			c.JSON(500, utils.EncodeError(gin.H{"error": "Not an admin"}))
			return
		}
		res, err := database.GetRadcheck()
		if err != nil {
			c.JSON(500, utils.EncodeError(gin.H{"error": "DB err"}))
			return
		}
		c.JSON(200, utils.EncodeSuccess(res))
	}
	return gin.HandlerFunc(fn)
}
