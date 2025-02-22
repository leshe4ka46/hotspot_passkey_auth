package utils

import (
	"math/rand"

	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func NewUUIDV4() string {
	return uuid.NewV4().String()
}

func EncodeError(err any) gin.H {
	switch v := err.(type) {
	case error:
		return gin.H{"status": "error", "error": v.Error()}
	case gin.H:
		v["status"] = "error"
		return v
	default:
		return gin.H{"status": "error", "error": v}
	}
}

func EncodeSuccess(data any) gin.H {
	return gin.H{"status": "OK", "data": data};
}