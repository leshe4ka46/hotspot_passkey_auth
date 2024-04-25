package server

import (
	_ "fmt"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/handlers"
	"hotspot_passkey_auth/wa"
	"log"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
)

func staticCacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			c.Header("Cache-Control", "private, max-age=86400")
		}
		c.Next()
	}
}

func InitServer(database *db.DB, wba *webauthn.WebAuthn, cfg *wa.Config) *gin.Engine {
	var router = gin.Default()
	router.Use(staticCacheMiddleware())
	router.StaticFile("/", consts.DistPath+"index.html")
	router.StaticFS("/static", http.Dir(consts.DistPath+"static"))
	router.StaticFile("/favicon.ico", consts.DistPath+"favicon.ico")
	router.StaticFile("/manifest.json", consts.DistPath+"manifest.json")
	router.StaticFile("/robots.txt", consts.DistPath+"robots.txt")
	router.StaticFile("/logo192.png", consts.DistPath+"logo192.png")
	router.StaticFile("/logo512.png", consts.DistPath+"logo512.png")

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

func StartServer(router *gin.Engine) {
	_cors := cors.Options{
		AllowedMethods: []string{"POST", "GET"},
		AllowedOrigins: []string{"http://localhost:8080", "http://192.168.88.246/"},
	}
	handler := cors.New(_cors).Handler(router)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
