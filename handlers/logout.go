package handlers

import (
	"github.com/gin-gonic/gin"
	"hotspot_passkey_auth/consts"
)

func LogoutHandler(c *gin.Context) {
	c.SetCookie(consts.LoginCookieName, "", 0, "/", consts.CookieDomain, false, true)
	c.JSON(200, gin.H{"status": "OK"})
}
