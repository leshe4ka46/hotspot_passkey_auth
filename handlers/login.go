package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
)

type LoginStruct struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Mac      string `json:"mac"`
}

type Base64Cookie struct {
	Hash string `json:"hash"`
	Mac  string `json:"mac"`
}

func LoginHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		var login LoginStruct
		err := c.BindJSON(&login)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user, err := database.CheckUsernamePassword(login.Username, login.Password)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user.Cookies = append(user.Cookies, db.CookieData{Cookie: cookie})
		user.Mac = db.AddStr(user.Mac, login.Mac)
		if err := database.DelUserByCookie(cookie); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		if err := database.UpdateUser(user); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		c.JSON(200, gin.H{"status": login.Username})
	}
	return gin.HandlerFunc(fn)
}
