package handlers

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
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
			cookies = append(cookies[:i],cookies[i+1:]...)
		}
	}
	tmp, _ := json.Marshal(macs)
	newm = string(tmp)
	tmp, _ = json.Marshal(cookies)
	newc = string(tmp)
	return
}

func LogoutHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user, err := database.GetUserByCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user.Mac, user.Cookies = RemoveMacCookie(user.Mac, user.Cookies, cookie)
		database.UpdateUser(user)
		c.SetCookie(consts.LoginCookieName, "", 0, "/", consts.CookieDomain, false, true)
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
