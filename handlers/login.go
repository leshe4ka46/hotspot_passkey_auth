package handlers

import (
	"fmt"
	"github.com/gin-gonic/gin"
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
		c.BindJSON(&login)
		user, err := database.GocheckAuth(login.Username, login.Password)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		fmt.Printf("%+v\n", user)
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user.Cookies = db.AddStr(user.Cookies,cookie)
		user.Mac = db.AddStr(user.Mac,login.Mac)
		database.UpdateUser(user)
		database.DelByCookie(cookie)
		c.JSON(200, gin.H{"status": login.Username})
	}
	return gin.HandlerFunc(fn)
}
