package wa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/store"
	"io/ioutil"
)

func AttestationGet(database *gorm.DB, wba *webauthn.WebAuthn, config *Config, userProvider *store.SessionProvider) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}
		db_user, err := db.GetUserByCookie(database, cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}
		fmt.Printf("%+v\n", db_user)
		user := store.User{
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
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}
		opts.Response.AuthenticatorSelection.AuthenticatorAttachment = ""
		opts.Response.AuthenticatorSelection.ResidentKey = "required" // ios fix
		opts.Response.CredentialExcludeList=[]protocol.CredentialDescriptor{};
		opts.Response.Extensions=protocol.AuthenticationExtensions{"credProps":true}
		db_user.Webauthn = JSONString(data)
		db_user.WebauthnUser = JSONString(user)
		db.UpdateUser(database, db_user)
		c.JSON(200, gin.H{"status": "OK", "data": opts})
	}
	return gin.HandlerFunc(fn)
}

func AttestationPost(database *gorm.DB, wba *webauthn.WebAuthn, config *Config, userProvider *store.SessionProvider) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		cookie, err := c.Cookie(consts.LoginCookieName)
		if err != nil {
			c.JSON(404, gin.H{"error": "Cookie not found"})
			return
		}
		db_user, err := db.GetUserByCookie(database, cookie)
		if err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		fmt.Printf("usr: %+v\n", db_user)
		var user store.User
		json.Unmarshal([]byte(db_user.WebauthnUser), &user)
		var webauthnData webauthn.SessionData
		json.Unmarshal([]byte(db_user.Webauthn), &webauthnData)
		var creds []webauthn.Credential
		json.Unmarshal([]byte(db_user.Credentials), &creds)
		jsonData, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(404, gin.H{"error": "Body not found"})
			return
		}
		fmt.Printf("%+v\n", user)
		fmt.Printf("%+v\n", webauthnData)
		fmt.Printf("%+v\n", creds)
		fmt.Println(string(jsonData))
		parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(jsonData))
		if err != nil {
			fmt.Println(err)
			c.JSON(404, gin.H{"error": "Body parce error"})
			return
		}
		cred, err := wba.CreateCredential(user, webauthnData, parsedResponse)
		if err != nil {
			c.JSON(404, gin.H{"error": "Could not create credential"})
			return
		}
		creds = append(creds, *cred)
		db_user.Credentials = JSONString(creds)
		db_user.Webauthn = ""
		db.UpdateUser(database, db_user)
		db.AddUserMac(database, db_user.Mac)
		c.JSON(200, gin.H{"status": "OK", "data": "ok"})
	}
	return gin.HandlerFunc(fn)
}
