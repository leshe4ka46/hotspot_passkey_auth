package wa

import (
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"

	"bytes"
	"errors"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"
)

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
		db_user.SessionData = *sessionData
		if err := database.UpdateUser(db_user); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		c.JSON(200, gin.H{"status": "OK", "data": assertion})
	}
	return gin.HandlerFunc(fn)
}

func AssertionPost(database *db.DB, wba *webauthn.WebAuthn, config *Config) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		var (
			credential     *webauthn.Credential
			parsedResponse *protocol.ParsedCredentialAssertionData
			err            error
		)
		postData, err := io.ReadAll(c.Request.Body)
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
		db_user_old, err := database.GetUserByCookie(cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		var db_user_key db.Gocheck
		//fmt.Printf("paesedresp: %+v\n", parsedResponse)
		if _, credential, err = wba.ValidatePasskeyLogin(func(_, userHandle []byte) (webauthn.User, error) {
			db_user_key, err = database.GetUserByUsername(string(userHandle))
			if err != nil {
				return &User{}, errors.New("user not found")
			}
			var creds []webauthn.Credential
			for _, cred := range db_user_key.Creds {
				creds = append(creds, cred.ToCredentials())
			}
			asserting_user := &User{
				ID:          string(db_user_key.Username),
				Name:        string(userHandle),
				DisplayName: string(userHandle),
				Credentials: creds,
			}
			return asserting_user, nil
		}, db_user_old.SessionData, parsedResponse); err != nil {
			c.JSON(404, gin.H{"error": "key validating error"})
			log.Error().Err(err).Msg("ValidateDiscoverableLogin error")
			return
		}

		var found = false
		var i int
		for i, cred := range db_user_key.Creds {
			if bytes.Equal(cred.PublicKey, (*credential).PublicKey) {
				db_user_key.Creds[i] = db.ToWaData(*credential, db_user_key.Creds[i].Id)
				// if err := database.UpdateCred(db_user_key.Creds[i]); err != nil {
				// 	log.Error().Err(err).Msg("")
				// 	c.JSON(404, gin.H{"error": "DB err"})
				// 	return
				// }
				found = true
				break
			}
		}
		if !found {
			i = len(db_user_key.Creds)
			db_user_key.Creds = append(db_user_key.Creds, db.ToWaData(*credential, db_user_key.Id))
		}
		db_user_key.Creds[i].GocheckUserId = db_user_key.Id
		if err := database.UpdateCred(db_user_key.Creds[i]); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		db_user_key.Creds = []db.WebauthnData{}

		if !credential.Authenticator.CloneWarning {
			db_user_key.Cookies = append(db_user_key.Cookies, db.CookieData{Cookie: cookie})
		}
		db_user_key.SessionData = webauthn.SessionData{}
		if err := database.UpdateUser(db_user_key); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		if credential.Authenticator.CloneWarning {
			c.JSON(404, gin.H{"error": "Key may be cloned one, restart auth with credentials"})
			log.Error().Err(err).Msg("CloneWarning == true")
			return
		}
		if err := database.DelUserByUsername(db_user_old.Username); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}

		log.Info().Str("mac:", c.Query("mac")).Msg("")
		//c.SetCookie(consts.LoginCookieName, db.GetFirst(db_user.Cookies), consts.CookieLifeTime, "/", consts.CookieDomain, false, true)
		if err := database.AddMacRadcheck(c.Query("mac")); err != nil {
			log.Error().Err(err).Msg("")
			// c.JSON(404, gin.H{"error": "DB err"}) // may be duplicate error, ignore
			//return
		}
		c.JSON(200, gin.H{"status": "OK"})
	}
	return gin.HandlerFunc(fn)
}
