package wa

import (
	"fmt"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/utils"

	"bytes"
	"io"

	"github.com/gin-gonic/gin"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/rs/zerolog/log"
)

func AttestationGet(database *db.DB, wba *webauthn.WebAuthn, config *Config) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}
		db_user, err := database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}

		user := User{
			ID:          db_user.Username,
			Name:        db_user.Username,
			DisplayName: db_user.Username,
		}

		selection := config.AuthenticatorSelection(protocol.ResidentKeyRequirementRequired) // discoverable
		opts, data, err := wba.BeginRegistration(user,
			webauthn.WithAuthenticatorSelection(selection),
			webauthn.WithConveyancePreference(config.ConveyancePreference),
			webauthn.WithExclusions(user.WebAuthnCredentialDescriptors()),
			webauthn.WithAppIdExcludeExtension(config.ExternalURL.String()),
		)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}

		// fixups for iphones
		opts.Response.AuthenticatorSelection.AuthenticatorAttachment = ""
		opts.Response.AuthenticatorSelection.ResidentKey = "required" // ios fix
		opts.Response.CredentialExcludeList = []protocol.CredentialDescriptor{}
		opts.Response.Extensions = protocol.AuthenticationExtensions{"credProps": true}

		db_user.SessionData = *data
		err = database.UpdateUser(db_user)
		if err != nil {
			log.Error().Err(err).Msg("")
		}
		c.JSON(200, gin.H{"status": "OK", "data": opts})
	}
	return gin.HandlerFunc(fn)
}

func AttestationPost(database *db.DB, wba *webauthn.WebAuthn, config *Config) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			log.Info().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "Cookie not found"})
			return
		}
		db_user, err := database.GetUserByCookie(cookie)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		user := User{
			ID:          db_user.Username,
			Name:        db_user.Username,
			DisplayName: db_user.Username,
		}

		jsonData, err := io.ReadAll(c.Request.Body)
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "Body not found"})
			return
		}

		parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(jsonData))
		if err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "Body parce error"})
			return
		}
		fmt.Printf("parsedResponse: %+v\n", parsedResponse)
		cred, err := wba.CreateCredential(user, db_user.SessionData, parsedResponse)
		if err != nil {
			log.Error().Err(err).Msg("CreateCredential error")
			c.JSON(404, gin.H{"error": "Could not create credential"})
			return
		}
		db_user.Creds = append(db_user.Creds, db.ToWaData(*cred, utils.NewUUIDV4()))
		db_user.SessionData = webauthn.SessionData{}
		if err := database.UpdateUser(db_user); err != nil {
			log.Error().Err(err).Msg("")
			c.JSON(404, gin.H{"error": "DB err"})
			return
		}
		//database.AddMacRadcheck(db.GetMacByCookie(db_user.Mac,db_user.Cookies,cookie))
		log.Info().Str("mac:", c.Query("mac")).Msg("")
		if err := database.AddMacRadcheck(c.Query("mac")); err != nil {
			log.Error().Err(err).Msg("")
			// c.JSON(404, gin.H{"error": "DB err"}) // may be duplicate error, ignore
			// return
		}
		c.JSON(200, gin.H{"status": "OK", "data": "ok"})
	}
	return gin.HandlerFunc(fn)
}
