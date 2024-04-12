package handlers

import (
	"encoding/base64"
	"encoding/json"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func getMacFromCookie(cookie string) (mac string, err error) {
	str, err := base64.RawStdEncoding.DecodeString(cookie)
	if err != nil {
		return
	}
	var base64Cookie Base64Cookie
	err = json.Unmarshal(str, &base64Cookie)
	if err != nil {
		return
	}
	mac = base64Cookie.Mac
	return
}

func NoKeysHandler(database *gorm.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		_, err = db.GetUserByCookie(database, cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		mac, err := getMacFromCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		db.AddUserMac(database, mac)
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
