package server

import (
	"embed"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/handlers"
	"hotspot_passkey_auth/wa"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
	"github.com/rs/zerolog/log"
)

func staticCacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			c.Header("Cache-Control", "private, max-age=86400")
		}
		c.Next()
	}
}

func bindataHandler(fs embed.FS) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		path := c.Request.URL.Path
		if path == "/" || path == "" {
			path = "index.html"
		} else {
			path = path[1:]
		}
		data, err := fs.ReadFile("dist/" + path)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found", "path": path})
			return
		}

		c.Writer.WriteHeader(http.StatusOK)
		c.Writer.Header().Set("Content-Type", http.DetectContentType(data))
		if _, err := c.Writer.Write(data); err != nil {
			log.Error().Err(err).Msg("error while sending data")
		}
	}
	return gin.HandlerFunc(fn)
}

func InitServer(database *db.DB, wba *webauthn.WebAuthn, cfg *wa.Config, fs embed.FS) *gin.Engine {
	var router = gin.Default()
	router.Use(staticCacheMiddleware())
	router.NoRoute(bindataHandler(fs))

	router.GET(consts.InfoPath, handlers.InfoHandler(database))
	router.POST(consts.LoginPath, handlers.LoginHandler(database))
	router.GET(consts.LogoutPath, handlers.LogoutHandler(database))
	router.POST(consts.LoginWithoutKeysPath, handlers.NoKeysHandler(database))

	router.GET(consts.AttestationPath, wa.AttestationGet(database, wba, cfg))
	router.POST(consts.AttestationPath, wa.AttestationPost(database, wba, cfg))

	router.GET(consts.AssertionPath, wa.AssertionGet(database, wba, cfg))
	router.POST(consts.AssertionPath, wa.AssertionPost(database, wba, cfg))

	router.GET(consts.AdminPath, handlers.AdminHandler(database))

	return router
}

func StartServer(router *gin.Engine) error {
	_cors := cors.Options{
		AllowedMethods: []string{"POST", "GET"},
		AllowedOrigins: []string{"http://localhost:8080", "http://192.168.88.246/"},
	}
	handler := cors.New(_cors).Handler(router)
	return http.ListenAndServe(":8080", handler)
}
