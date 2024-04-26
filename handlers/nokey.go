package handlers

import (
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"encoding/json"
	"github.com/gin-gonic/gin"
)

func GetMacByCookie(m string, c string, cookie string) (mac string) {
	var macs, cookies []string
	json.Unmarshal([]byte(m), &macs)
	json.Unmarshal([]byte(c), &cookies)
	for i, c := range cookies {
		if string(c) == cookie {
			return macs[i]
		}
	}
	return ""
}

func NoKeysHandler(database *db.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "Cookie get err"})
			return
		}
		db_user, err := database.GetUserByCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		database.AddMacRadcheck(GetMacByCookie(db_user.Mac,db_user.Cookies,cookie))
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
