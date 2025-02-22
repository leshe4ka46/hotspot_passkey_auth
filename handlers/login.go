package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/utils"
)

type LoginStruct struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func LoginHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		var login LoginStruct
		err := c.BindJSON(&login)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "Bad json payload: " + err.Error()}))
			return
		}
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil || cookie == "" {
			log.Info().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "Bad cookie"}))
			return
		}
		user, err := database.CheckUsernamePassword(login.Username, login.Password)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "User not found"}))
			return
		}
		user.Cookies = append(user.Cookies, db.CookieData{Cookie: cookie})
		if err := database.DelUserByCookie(cookie); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "DB err"}))
			return
		}
		if err := database.UpdateUser(user); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "DB err"}))
			return
		}
		c.JSON(200, utils.EncodeSuccess(gin.H{"username": login.Username}))
	}
	return gin.HandlerFunc(fn)
}
