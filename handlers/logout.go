package handlers

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/utils"
)

func RemoveMacCookie(m string, c string, cookie string) (newm, newc string) {
	var macs, cookies []string
	json.Unmarshal([]byte(m), &macs)
	json.Unmarshal([]byte(c), &cookies)
	for i, c := range cookies {
		if string(c) == cookie {
			macs = append(macs[:i], macs[i+1:]...)
			cookies = append(cookies[:i], cookies[i+1:]...)
		}
	}
	tmp, _ := json.Marshal(macs)
	newm = string(tmp)
	tmp, _ = json.Marshal(cookies)
	newc = string(tmp)
	return
}

func arrRemove(arr []db.CookieData, cookie string) (newarr []db.CookieData) {
	for i, v := range arr {
		if v.Cookie == cookie {
			newarr = append(arr[:i], arr[i+1:]...)
			break
		}
	}
	return
}

func LogoutHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "User not found"}))
			return
		}
		_, err = database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "User not found"}))
			return
		}
		if err := database.DelCookie(cookie); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(500, utils.EncodeError(gin.H{"error": "DB err"}))
			return
		}
		//user.Mac, user.Cookies = RemoveMacCookie(user.Mac, user.Cookies, cookie)
		c.SetCookie(consts.LoginCookieName, "", 0, "/", consts.CookieDomain, false, true)
		c.JSON(200, utils.EncodeSuccess(gin.H{}))
	}
	return gin.HandlerFunc(fn)
}
