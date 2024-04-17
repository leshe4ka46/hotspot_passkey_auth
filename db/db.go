package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"hotspot_passkey_auth/consts"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DB struct {
	db *gorm.DB
}

type Database interface {
	GocheckAuth(username string, password string) (gocheck Gocheck, err error)
	AddUser(user *Gocheck) (err error)
	GetUserByCookie(cookie string) (gocheck Gocheck, err error)
	UpdateUser(gocheck Gocheck) (err error)
	GetUserByUsername(uname string) (gocheck Gocheck, err error)
	AddMacRadcheck(mac string) (err error)
	DelByCookie(cookie string) (err error)
	GetRadcheck() (res []Radacct,err error)
	ExpireMacUsers() (err error)
}

type Radcheck struct {
	Id          uint   `gorm:"primaryKey"`
	Username    string `gorm:"type:varchar(64);uniqueIndex"`
	Attribute   string `gorm:"type:varchar(64)"`
	Op          string `gorm:"type:varchar(2)"`
	Value       string `gorm:"type:varchar(253)"`
	CreatedTime int64  `gorm:"type:integer"`
}

func (Radcheck) TableName() string {
	return "radcheck"
}

type Gocheck struct {
	Id                uint   `gorm:"primaryKey"`
	Username          string `gorm:"type:varchar(64);uniqueIndex"`
	Password          string `gorm:"type:varchar(64)"`
	Mac               string `gorm:"type:varchar(17)"`
	Credentials       string `gorm:"type:string"`
	CredentialsSignIn string `gorm:"type:string"`
	Cookies           string `gorm:"type:string"`
	Webauthn          string `gorm:"type:string"`
	WebauthnUser      string `gorm:"type:string"`
	IsAdmin           bool   `gorm:"type:boolean"`
}

func (Gocheck) TableName() string {
	return "gocheck"
}

type Radacct struct {
	Radacctid          uint   `gorm:"primaryKey"`
	Acctsessionid      string `gorm:"type:varchar(64)"`
	Acctuniqueid       string `gorm:"type:varchar(32)"`
	Username           string `gorm:"type:varchar(64)"`
	Realm              string `gorm:"type:varchar(64)"`
	Nasipaddress       string `gorm:"type:varchar(15)"`
	Nasportid          string `gorm:"type:varchar(15)"`
	Nasporttype        string `gorm:"type:varchar(32)"`
	Acctstarttime      time.Time
	Acctupdatetime     time.Time
	Acctstoptime       time.Time
	Acctinterval       int
	Acctsessiontime    int
	Acctauthentic      string `gorm:"type:varchar(32)"`
	ConnectinfoStart   string `gorm:"type:varchar(50)"`
	ConnectinfoStop    string `gorm:"type:varchar(50)"`
	Acctinputoctets    uint
	Acctoutputoctets   uint
	Calledstationid    string `gorm:"type:varchar(50)"`
	Callingstationid   string `gorm:"type:varchar(50)"`
	Acctterminatecause string `gorm:"type:varchar(32)"`
	Servicetype        string `gorm:"type:varchar(32)"`
	Framedprotocol     string `gorm:"type:varchar(32)"`
	Framedipaddress    string `gorm:"type:varchar(15)"`
	Framedipv6address  string `gorm:"type:varchar(45)"`
	Framedipv6prefix   string `gorm:"type:varchar(45)"`
	Framedinterfaceid  string `gorm:"type:varchar(32)"`
	Deligateipv6prefix string `gorm:"type:varchar(45)"`
	Class              string `gorm:"type:varchar(32)"`
}

func (Radacct) TableName() string {
	return "radacct"
}

func Connect(user, password, host, port, dbname string) *DB {
	db, err := Oldconnect(user, password, host, port, dbname)
	if err != nil {
		return nil
	}
	return &DB{
		db: db,
	}
}

func Oldconnect(user, password, host, port, dbname string) (db *gorm.DB, err error) {
	dbAddress := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, password, host, port, dbname)
	db, err = gorm.Open(postgres.Open(dbAddress))
	return
}

func (p *DB) GocheckAuth(username string, password string) (gocheck Gocheck, err error) {
	fields := []string{"username = ?", "password = ?"}
	values := []interface{}{username, password}
	err = p.db.Where(strings.Join(fields, " AND "), values...).First(&gocheck).Error
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
	json.Unmarshal([]byte(str), &arr)
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

func (p *DB) UpdateUser(gocheck Gocheck) (err error) {
	err = p.db.Model(gocheck).Where("username = ?", gocheck.Username).Update("cookies", string(gocheck.Cookies)).Update("mac", string(gocheck.Mac)).Update("credentials", string(gocheck.Credentials)).Update("webauthn", string(gocheck.Webauthn)).Update("webauthn_user", string(gocheck.WebauthnUser)).Update("credentials_sign_in", string(gocheck.CredentialsSignIn)).Error
	return
}

func (p *DB) GetUserByCookie(cookie string) (gocheck Gocheck, err error) {
	err = p.db.Where("cookies = ?", cookie).First(&gocheck).Error
	return
}

func (p *DB) AddMacRadcheck(mac string) (err error) {
	if mac == "" {
		return errors.New("no mac passed")
	}
	return p.db.Create(&Radcheck{Username: mac, Attribute: "Cleartext-Password", Op: ":=", Value: "8ud8HevunaNXmcTEcjkBWAzX0iuhc6JF", CreatedTime: time.Now().Unix()}).Error
}

func (p *DB) AddUser(user *Gocheck) (err error) {
	return p.db.Create(user).Error
}

func (p *DB) GetUserByUsername(uname string) (gocheck Gocheck, err error) {
	err = p.db.Where("username = ?", uname).First(&gocheck).Error
	return
}

func (p *DB) DelByCookie(cookie string) (err error) {
	return p.db.Delete(&Gocheck{}, "password = '' AND Cookies=?", cookie).Error
}

func (p *DB) GetRadcheck() (res []Radacct,err error) {
	err = p.db.Find(&res).Error
	return
}

func (p *DB) ExpireMacUsers() (err error) {
	err = p.db.Where("created_time < ?", time.Now().Unix()-consts.MacUserLifetime).Delete(&Radcheck{}).Error
	return
}
