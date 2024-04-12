package db

import (
	"encoding/json"
	"fmt"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Radcheck struct {
	Id        uint   `gorm:"primaryKey"`
	Username  string `gorm:"type:varchar(64);uniqueIndex"`
	Attribute string `gorm:"type:varchar(64)"`
	Op        string `gorm:"type:varchar(2)"`
	Value     string `gorm:"type:varchar(253)"`
}

func (Radcheck) TableName() string {
	return "radcheck"
}

type Gocheck struct {
	Id          uint   `gorm:"primaryKey"`
	Username    string `gorm:"type:varchar(64);uniqueIndex"`
	Password    string `gorm:"type:varchar(64)"`
	Mac         string `gorm:"type:varchar(17)"`
	Credentials string `gorm:"type:varchar"`
	Cookies     string `gorm:"type:string"`
}

func (Gocheck) TableName() string {
	return "gocheck"
}

func Connedt(user, password, host, port, dbname string) (db *gorm.DB, err error) {
	dbAddress := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, password, host, port, dbname)
	db, err = gorm.Open(postgres.Open(dbAddress))
	return
}

func GocheckGetUsernameAndPass(db *gorm.DB, username string, password string) (gocheck Gocheck, err error) {
	fields := []string{"username = ?", "password = ?"}
	values := []interface{}{username, password}
	err = db.Where(strings.Join(fields, " AND "), values...).First(&gocheck).Error
	return
}

func contains(arr []string, name string) bool {
	for _, value := range arr {
		if value == name {
			return true
		}
	}
	return false
}

func addToArray(str string, value string) (err error, result string) {
	var arr []string
	err = json.Unmarshal([]byte(str), &arr)
	if err != nil {
		return
	}
	if !contains(arr, value) {
		arr = append(arr, value)
		var b []byte
		b, err = json.Marshal(arr)
		if err != nil {
			return
		}
		result = string(b)
		return
	}
	result = str
	return
}

func AddUserCookieAndMac(db *gorm.DB, gocheck Gocheck, cookie, mac string) (err error) {
	err, gocheck.Cookies = addToArray(gocheck.Cookies, cookie)
	if err != nil {
		return
	}
	err, gocheck.Mac = addToArray(gocheck.Mac, mac)
	if err != nil {
		return
	}
	err = db.Model(gocheck).Where("username = ?", gocheck.Username).Update("cookies", string(gocheck.Cookies)).Update("mac", string(gocheck.Mac)).Error
	return
}

func GetUserByCookie(db *gorm.DB, cookie string) (gocheck Gocheck, err error) {
	err = db.Where("strpos(cookies,?)>0", cookie).First(&gocheck).Error
	return
}

func AddUserMac(db *gorm.DB, mac string) (err error) {
	return db.Create(&Radcheck{Username: mac, Attribute: "Cleartext-Password", Op: ":=", Value: "8ud8HevunaNXmcTEcjkBWAzX0iuhc6JF"}).Error
}