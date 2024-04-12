package main

import (
	_"fmt"
	"hotspot_passkey_auth/db"
	"hotspot_passkey_auth/server"
	"log"
	"os"

	"github.com/joho/godotenv"
)

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
	r := server.InitServer(database)
	server.StartServer(r)
}

/*
res, err := db.GetRadcheckByUsername(database, "leshe4kamac")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", res);
*/
