package db

import (
	"errors"
	"fmt"
	"hotspot_passkey_auth/consts"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DB struct {
	db *gorm.DB
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
	Id       string `gorm:"primaryKey"`
	Username string `gorm:"type:varchar(64);uniqueIndex"`
	Password string `gorm:"typce:varchar(64)"`

	SessionData webauthn.SessionData `gorm:"serializer:json"`
	IsAdmin     bool

	Creds   []WebauthnData `gorm:"foreignKey:GocheckUserId"`
	Cookies []CookieData   `gorm:"foreignKey:GocheckUserId"`
}

func (Gocheck) TableName() string {
	return "gocheck"
}

type WebauthnData struct {
	Id   string `gorm:"type:varchar(37);primaryKey"`
	Name string `gorm:"type:varchar(64)"`
	// LowerName       string
	// UserID          int64
	CredentialID    []byte `gorm:"size:1024"`
	PublicKey       []byte `gorm:"uniqueIndex"`
	AttestationType string 
	AAGUID          []byte
	SignCount       uint32
	CloneWarning    bool
	BackupEligible  bool
	CreatedUnix     time.Time `gorm:"index;autoCreateTime"`
	UpdatedUnix     time.Time `gorm:"index;autoUpdateTime"`

	GocheckUserId string
	User          Gocheck `gorm:"foreignKey:GocheckUserId;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

func (WebauthnData) TableName() string {
	return "webauthn-data"
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

func ToWaData(data webauthn.Credential, id string) WebauthnData {
	return WebauthnData{
		Id:              id,
		CredentialID:    data.ID,
		PublicKey:       data.PublicKey,
		AttestationType: data.AttestationType,
		AAGUID:          data.Authenticator.AAGUID,
		SignCount:       data.Authenticator.SignCount,
		CloneWarning:    data.Authenticator.CloneWarning,
		BackupEligible:  data.Flags.BackupEligible,
	}
}

type CookieData struct {
	//Id     string   `gorm:"primaryKey"`
	Cookie string `gorm:"primaryKey"`

	GocheckUserId string
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
	db, err = gorm.Open(postgres.Open(dbAddress), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error), // Set the logger in the GORM config
	})
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
	return p.db.Model(&cred).Updates(cred). // save does not recognise id if it is zero
		// Where("id = ?", cred.Id).
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
	// for _, cred := range gocheck.Creds {
	// 	if err := p.UpdateCred(cred); err != nil {
	// 		return err
	// 	}
	// }
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

func (p *DB) DelUserByUsername(uname string) error {
	var dat Gocheck
	if err := p.db.Preload("Cookies").First(&dat, "username = ?", uname).Error; err != nil {
		return err
	}
	for _, cookie := range dat.Cookies {
		if err := p.db.Delete(cookie).Error; err != nil {
			return err
		}
	}
	return p.db.Delete(dat).Error
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
