package server

import (
	_ "fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/handlers"
	"log"
	"net/http"
	"strings"
	"gorm.io/gorm"
)

func staticCacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			c.Header("Cache-Control", "private, max-age=86400")
		}
		c.Next()
	}
}

func InitServer(database *gorm.DB) *gin.Engine {
	var router = gin.Default()
	router.Use(staticCacheMiddleware())
	router.StaticFile("/", "./dist/index.html")
	router.StaticFS("/static", http.Dir("./dist/static"))
	router.StaticFile("/favicon.ico", "./dist/favicon.ico")
	router.StaticFile("/manifest.json", "./dist/manifest.json")
	router.StaticFile("/robots.txt", "./dist/robots.txt")
	router.StaticFile("/logo192.png", "./dist/logo192.png")
	router.StaticFile("/logo512.png", "./dist/logo512.png")

	router.GET(consts.InfoPath, handlers.InfoHandler(database))
	router.POST(consts.LoginPath, handlers.LoginHandler(database))
	router.POST(consts.LoginWithoutKeysPath, handlers.NoKeysHandler(database))


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
