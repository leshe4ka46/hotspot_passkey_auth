package server

import (
	"embed"
	_ "fmt"
	"github.com/go-webauthn/webauthn/webauthn"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/handlers"
	"hotspot_passkey_auth/wa"
	"net/http"
	"strings"

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

func bindataStaticHandler(fs embed.FS) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		path := c.Param("filepath")
		data, err := fs.ReadFile("dist/static" + path)
		if err != nil {
			c.JSON(404, gin.H{"error": "not found", "path": "dist/static" + path})
		}
		c.Writer.Write(data)
	}
	return gin.HandlerFunc(fn)
}

func BindataHandler(path string, fs embed.FS) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		data, err := fs.ReadFile("dist/" + path)
		if err != nil {
			c.JSON(404, gin.H{"error": "not found", "path": "dist/" + path})
		}
		c.Writer.Write(data)
	}
	return gin.HandlerFunc(fn)
}

func InitServer(database *db.DB, wba *webauthn.WebAuthn, cfg *wa.Config, fs embed.FS) *gin.Engine {
	var router = gin.Default()
	router.Use(staticCacheMiddleware())
	router.GET("/", BindataHandler("index.html", fs))
	router.GET("/static/*filepath", bindataStaticHandler(fs))
	router.GET("/favicon.ico", BindataHandler("favicon.ico", fs))
	router.GET("/manifest.json", BindataHandler("manifest.json", fs))
	router.GET("/robots.txt", BindataHandler("robots.txt", fs))
	router.GET("/logo192.png", BindataHandler("logo192.png", fs))
	router.GET("/logo512.png", BindataHandler("logo512.png", fs))

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
