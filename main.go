package main

import (
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/server"
	"hotspot_passkey_auth/wa"
	"hotspot_passkey_auth/consts"
	"fmt"
	"net/url"
	"os"
	"time"
	"embed"
	"github.com/joho/godotenv"
)

func ExpireUsers(database *db.DB){
	for {
		database.ExpireMacUsers()
		time.Sleep(time.Duration(consts.MacExpirePollTime)*time.Second)
	}
}

//go:embed dist
var fs embed.FS

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Printf("Error loading .env file")
	}
	consts.UpdConsts();
	database:=db.Connect(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME"))

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
	r := server.InitServer(database, webauthn, &config,fs)
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
