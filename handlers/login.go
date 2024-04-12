package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type LoginStruct struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Mac      string `json:"mac"`
}

type Base64Cookie struct {
	Hash string `json:"hash"`
	Mac string `json:"mac"`
}

func hexSha256(uname string, pass string, mac string) string {
	h := sha256.New()
	h.Write([]byte(uname+pass+mac))
	hash:=base64.RawStdEncoding.EncodeToString(h.Sum(nil))
	bytes, _ := json.Marshal(Base64Cookie{Hash: hash, Mac: mac})
	return base64.RawStdEncoding.EncodeToString(bytes)
}

func LoginHandler(database *gorm.DB) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		var login LoginStruct
		c.BindJSON(&login)
		user, err := db.GocheckGetUsernameAndPass(database, login.Username, login.Password)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		fmt.Printf("%+v\n",user);
		cookie := hexSha256(user.Username,user.Password,login.Mac)
		err=db.AddUserCookieAndMac(database, user, cookie, login.Mac)
		if err!=nil{
			fmt.Println("Error: ",err)
		}
		c.SetCookie(consts.LoginCookieName, cookie, consts.CookieLifeTime, "/", consts.CookieDomain, false, true)
		fmt.Println("Cookie: ", cookie)
		c.JSON(200, gin.H{"status": login.Username})
	}
	return gin.HandlerFunc(fn)
}
