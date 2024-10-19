package wa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"io/ioutil"
)

func bytearreq(a, b []byte) bool {
	for i, dat := range a {
		if dat != b[i] {
			return false
		}
	}
	return true
}

func AssertionGet(database *db.DB, wba *webauthn.WebAuthn, config *Config) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		var opts = []webauthn.LoginOption{
			webauthn.WithUserVerification(protocol.VerificationPreferred),
		}
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "Cookie not found"})
			return
		}
		db_user, err := database.GetUserByCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		var (
			assertion   *protocol.CredentialAssertion
			sessionData *webauthn.SessionData
		)
		if assertion, sessionData, err = wba.BeginDiscoverableLogin(opts...); err != nil {
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}
		db_user.SessionData = JSONString(sessionData)
		if err := database.UpdateUser(db_user); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		c.JSON(200, gin.H{"status": "OK", "data": assertion})
	}
	return gin.HandlerFunc(fn)
}

type MacFromAssertion struct {
	Mac string `json:"mac"`
}

func AssertionPost(database *db.DB, wba *webauthn.WebAuthn, config *Config) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		var (
			credential     *webauthn.Credential
			parsedResponse *protocol.ParsedCredentialAssertionData
			err            error
		)
		postData, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(404, gin.H{"error": "Body not found"})
			return
		}
		if parsedResponse, err = protocol.ParseCredentialRequestResponseBody(bytes.NewReader(postData)); err != nil {
			c.JSON(404, gin.H{"error": "Error parsing body"})
			return
		}
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "Cookie not found"})
			return
		}
		db_user, err := database.GetUserByCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		var webauthnData webauthn.SessionData
		json.Unmarshal([]byte(db_user.SessionData), &webauthnData)

		if credential, err = wba.ValidateDiscoverableLogin(func(_, userHandle []byte) (webauthn.User, error) {
			fmt.Println("userHandle:", string(userHandle))
			db_user, err = database.GetUserByUsername(string(userHandle))
			if err != nil {
				return &User{}, errors.New("user not found")
			}
			var creds []webauthn.Credential
			for _, cred := range db_user.Creds {
				creds = append(creds, cred.ToCredentials())
			}
			asserting_user := &User{
				ID:          string(db_user.Username),
				Name:        string(userHandle),
				DisplayName: string(userHandle),
				Credentials: creds,
			}
			return asserting_user, nil
		}, webauthnData, parsedResponse); err != nil {
			c.JSON(404, gin.H{"error": "ValidateDiscoverableLogin error"})
			log.Error().Err(err).Msg("ValidateDiscoverableLogin error")
			return
		}
		var macData MacFromAssertion
		json.Unmarshal(postData, &macData)

		var found = false
		for i, cred := range db_user.Creds {
			if bytearreq(cred.PublicKey, (*credential).PublicKey) {
				db_user.Creds[i] = db.ToWaData(*credential,db_user.Id)
				if err := database.UpdateCred(db_user.Creds[i]); err != nil {
					log.Error().Err(err).Msg("")
					c.JSON(404, gin.H{"error": "DB err"})
					return
				}
				found = true
				break;
			}
		}
		if !found {
			db_user.Creds = append(db_user.Creds, db.ToWaData(*credential,db_user.Id))
		}
		db_user.Mac = db.AddStr(db_user.Mac, macData.Mac)
		db_user.Cookies = append(db_user.Cookies, db.CookieData{Cookie: cookie})
		db_user.Creds = []db.WebauthnData{}; // manually updated creds in upper code, because save method just adds new)
		if err := database.UpdateUser(db_user); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		if err := database.DelUserByCookie(cookie); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		//c.SetCookie(consts.LoginCookieName, db.GetFirst(db_user.Cookies), consts.CookieLifeTime, "/", consts.CookieDomain, false, true)
		// if err := database.AddMacRadcheck(macData.Mac); err != nil {
		// 	log.Error().Err(err).Msg("")
		// 	c.JSON(404, gin.H{"error": "DB err"})
		// 	return
		// }
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
