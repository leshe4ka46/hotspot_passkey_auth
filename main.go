package main

import (
	"embed"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"

	"hotspot_passkey_auth/consts"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/server"
	"hotspot_passkey_auth/wa"
	"net/url"
	"os"
	"time"
)

func ExpireUsers(database *db.DB) {
	for {
		if err := database.ExpireMacUsers(); err != nil {
			log.Error().Err(err).Msg("")
		}
		time.Sleep(time.Duration(consts.MacExpirePollTime) * time.Second)
	}
}

//go:generate ./build.sh
//go:embed web/build
var fs embed.FS
var basePath = "web/build/"

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Printf("Error loading .env file")
	}
	consts.UpdConsts()
	database, err := db.Connect(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME"))
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	url, err := url.Parse(os.Getenv("WEBAUTHN_EXTERNAL_URL"))
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	config := wa.Config{
		DisplayName:          os.Getenv("WEBAUTHN_DISPLAY_NAME"),
		RPID:                 os.Getenv("WEBAUTHN_RPID"),
		ExternalURL:          *url,
		ConveyancePreference: wa.ParceAttestationPreference(os.Getenv("WEBAUTHN_CONVEYANCE_PREFERENCE")),
	}
	webauthn, err := wa.InitWebauthn(config)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	r := server.InitServer(database, webauthn, &config, fs, basePath)

	go ExpireUsers(database)
	log.Fatal().Stack().Err(server.StartServer(r)).Msg("")
}

/*
res, err := db.GetRadcheckByUsername(database, "leshe4kamac")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", res);
*/
