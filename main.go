package main

import (
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/server"
	"hotspot_passkey_auth/wa"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

func ExpireUsers(database *gorm.DB){
	for {
		db.ExpireMacUsers(database)
		time.Sleep(60*time.Second)
	}
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	database, err := db.Connedt(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME"))
	if err != nil {
		panic(err)
	}
	database.AutoMigrate(&db.Gocheck{})
	database.AutoMigrate(&db.Radcheck{})

	url, err:= url.Parse(os.Getenv("WEBAUTHN_EXTERNAL_URL"))
	if err!=nil{
		panic(err)
	}
	config:=wa.Config{
		DisplayName:os.Getenv("WEBAUTHN_DISPLAY_NAME"),
		RPID:os.Getenv("WEBAUTHN_RPID"),
		ExternalURL: *url,
		ConveyancePreference: wa.ParceAttestationPreference(os.Getenv("WEBAUTHN_CONVEYANCE_PREFERENCE")),
	}
	webauthn, err := wa.InitWebauthn(config)
	if err!=nil{
		panic(err)
	}
	r := server.InitServer(database, webauthn, &config)
	go ExpireUsers(database)
	server.StartServer(r)
}

/*
res, err := db.GetRadcheckByUsername(database, "leshe4kamac")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", res);
*/
