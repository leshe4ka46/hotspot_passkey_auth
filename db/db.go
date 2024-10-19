package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-webauthn/webauthn/webauthn"
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
	CheckUsernamePassword(username string, password string) (gocheck Gocheck, err error)
	AddUser(user *Gocheck) (err error)
	GetUserByCookie(cookie string) (gocheck Gocheck, err error)
	UpdateUser(gocheck Gocheck) (err error)
	GetUserByUsername(uname string) (gocheck Gocheck, err error)
	AddMacRadcheck(mac string) (err error)
	DelUserByCookie(cookie string) (err error)
	DelCookie(cookie string) (err error)
	GetRadcheck() (res []Radacct, err error)
	ExpireMacUsers() (err error)
	UpdateCred(cred WebauthnData) error
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
	Id       uint   `gorm:"primaryKey"`
	Username string `gorm:"type:varchar(64);uniqueIndex"`
	Password string `gorm:"typce:varchar(64)"`
	Mac      string
	//Credentials  string
	SessionData string
	IsAdmin     bool

	Creds   []WebauthnData `gorm:"foreignKey:GocheckUserId"`
	Cookies []CookieData   `gorm:"foreignKey:GocheckUserId"`
}

func (Gocheck) TableName() string {
	return "gocheck"
}

type WebauthnData struct {
	Id              uint `gorm:"primaryKey"`
	Name            string
	LowerName       string
	UserID          int64
	CredentialID    []byte `gorm:"size:1024"`
	PublicKey       []byte `gorm:"uniqueIndex"`
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	CloneWarning    bool
	BackupEligible  bool
	CreatedUnix     time.Time // currently unused, was in gitea sources
	UpdatedUnix     time.Time // currently unused, was in gitea sources

	GocheckUserId uint
	User          Gocheck `gorm:"foreignKey:GocheckUserId;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

func (cred WebauthnData) ToCredentials() webauthn.Credential {
	return webauthn.Credential{
		ID:              cred.CredentialID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Authenticator: webauthn.Authenticator{
			AAGUID:       cred.AAGUID,
			SignCount:    cred.SignCount,
			CloneWarning: cred.CloneWarning,
		},
		Flags: webauthn.CredentialFlags{
			BackupEligible: cred.BackupEligible,
		},
	}
}

func ToWaData(data webauthn.Credential, gocheckuserid uint) WebauthnData {
	return WebauthnData{
		CredentialID:    data.ID,
		PublicKey:       data.PublicKey,
		AttestationType: data.AttestationType,
		AAGUID:          data.Authenticator.AAGUID,
		SignCount:       data.Authenticator.SignCount,
		CloneWarning:    data.Authenticator.CloneWarning,
		BackupEligible:  data.Flags.BackupEligible,
		GocheckUserId:   gocheckuserid,
	}
}

func (WebauthnData) TableName() string {
	return "webauthn-data"
}

type CookieData struct {
	Id     uint   `gorm:"primaryKey"`
	Cookie string `gorm:"type:string"`

	GocheckUserId uint
	User          Gocheck `gorm:"foreignKey:GocheckUserId;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

func (CookieData) CookieData() string {
	return "cookie-data"
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

func Connect(user, password, host, port, dbname string) (*DB, error) {
	db, err := Oldconnect(user, password, host, port, dbname)
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&Gocheck{}, &WebauthnData{}, &CookieData{}); err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&Radcheck{}); err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&Radacct{}); err != nil {
		return nil, err
	}
	return &DB{
		db: db,
	}, nil
}

func Oldconnect(user, password, host, port, dbname string) (db *gorm.DB, err error) {
	dbAddress := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, password, host, port, dbname)
	db, err = gorm.Open(postgres.Open(dbAddress))
	return
}

func (p *DB) CheckUsernamePassword(username string, password string) (gocheck Gocheck, err error) {
	fields := []string{"username = ?", "password = ?"}
	values := []interface{}{username, password}
	err = p.db.Where(strings.Join(fields, " AND "), values...).First(&gocheck).Error
	return
}

func (p *DB) UpdateCred(cred WebauthnData) error {
	// return p.db.Save(&cred).Error
	return p.db.Model(&cred).Where("id = ?", cred.Id).Updates(cred). // save does not recognise id if it is zero
		// Update("credential_id", cred.CredentialID).
		// Update("public_key", cred.PublicKey).
		// Update("attestation_type", cred.AttestationType).
		// Update("aa_guid", cred.AAGUID).
		// Update("sign_count", cred.SignCount).
		// Update("clone_warning", cred.CloneWarning).
		// Update("backup_eligible", cred.BackupEligible).
		Error
}

func (p *DB) UpdateUser(gocheck Gocheck) error {
	err := p.db.Save(&gocheck).Error
	return err
}

func (p *DB) GetUserByCookie(cookie string) (gocheck Gocheck, err error) {
	var dat CookieData
	err = p.db.Preload("User").First(&dat, "cookie = ?", cookie).Error
	gocheck = dat.User
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
	err = p.db.Preload("Creds").First(&gocheck, "username = ?", uname).Error
	return
}

func (p *DB) DelUserByCookie(cookie string) error {
	var dat CookieData
	if err := p.db.Preload("User").First(&dat, "cookie = ?", cookie).Error; err != nil {
		return err
	}
	if err := p.db.Delete(dat).Error; err != nil {
		return err
	}
	return p.db.Delete(dat.User).Error
}

func (p *DB) DelCookie(cookie string) error {
	return p.db.Delete(&CookieData{}, "cookie = ?", cookie).Error
}

func (p *DB) GetRadcheck() (res []Radacct, err error) {
	err = p.db.Find(&res).Error
	return
}

func (p *DB) ExpireMacUsers() (err error) {
	err = p.db.Where("created_time < ?", time.Now().Unix()-consts.MacUserLifetime).Delete(&Radcheck{}).Error
	return
}

func AddStr(in string, mac string) (out string) {
	var arr []string = []string{}
	if in != "" {
		json.Unmarshal([]byte(in), &arr)
	}
	arr = append(arr, mac)
	outb, _ := json.Marshal(arr)
	out = string(outb)
	return
}

func RemoveStr(in string, mac string) (out string) {
	var arr []string = []string{}
	var outarr []string
	if in != "" {
		json.Unmarshal([]byte(in), &arr)
	}
	for _, el := range arr {
		if el != mac {
			outarr = append(outarr, el)
		}
	}
	outb, _ := json.Marshal(outarr)
	out = string(outb)
	return
}

func GetFirst(in string) (out string) {
	var arr []string = []string{}
	if in == "" {
		return ""
	}
	json.Unmarshal([]byte(in), &arr)
	return arr[0]
}

func GetMacByCookie(m string, c string, cookie string) (mac string) {
	var macs, cookies []string
	json.Unmarshal([]byte(m), &macs)
	json.Unmarshal([]byte(c), &cookies)
	for i, c := range cookies {
		if string(c) == cookie {
			return macs[i]
		}
	}
	return ""
}
