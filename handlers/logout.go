package handlers

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
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
	for _, c := range arr {
		if c.Cookie != cookie {
			newarr = append(newarr, c)
		}
	}
	return
}

func LogoutHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user, err := database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user.Cookies = arrRemove(user.Cookies, cookie)
		if err := database.DelCookie(cookie); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		//user.Mac, user.Cookies = RemoveMacCookie(user.Mac, user.Cookies, cookie)
		if err := database.UpdateUser(user); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		c.SetCookie(consts.LoginCookieName, "", 0, "/", consts.CookieDomain, false, true)
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
