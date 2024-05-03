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

func bindataStaticHandler(c *gin.Context) {
	path := c.Param("filepath")
	data, err := Asset("dist/static" + path)
	if err != nil {
		c.JSON(404, gin.H{"error": "not found", "path": "dist/static" + path})
	}
	c.Writer.Write(data)
}

func BindataHandler(path string) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		data, err := Asset("dist/" + path)
		if err != nil {
			c.JSON(404, gin.H{"error": "not found", "path": "dist/" + path})
		}
		c.Writer.Write(data)
	}
	return gin.HandlerFunc(fn)
}

func InitServer(database *db.DB, wba *webauthn.WebAuthn, cfg *wa.Config) *gin.Engine {
	var router = gin.Default()
	router.Use(staticCacheMiddleware())
	router.GET("/", BindataHandler("index.html"))
	router.GET("/static/*filepath", bindataStaticHandler)
	router.GET("/favicon.ico", BindataHandler("favicon.ico"))
	router.GET("/manifest.json", BindataHandler("manifest.json"))
	router.GET("/robots.txt", BindataHandler("robots.txt"))
	router.GET("/logo192.png", BindataHandler("logo192.png"))
	router.GET("/logo512.png", BindataHandler("logo512.png"))

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
