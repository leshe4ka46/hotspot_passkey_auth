package consts

import (
	"os"
	"strconv"
)

const DistPath = "./dist/"

func toInt(s string) (i int) {
	i, _ = strconv.Atoi(s)
	return
}

var MacExpirePollTime = toInt(os.Getenv("MAC_EXPIRE_POLL_TIME"))

var CookieLifeTime = toInt(os.Getenv("COOKIE_LIFETIME"))

var MacUserLifetime = int64(toInt(os.Getenv("RADCHECK_LIFETIME")))

const LoginCookieName = "loginCookie"

var CookieDomain = os.Getenv("COOKIE_DOMAIN")

const SecureCookie = false

const apiPath = "/api"
const LoginPath = apiPath + "/login"
const LogoutPath = apiPath + "/logout"

const InfoPath = apiPath + "/info"
const LoginWithoutKeysPath = apiPath + "/radius/login"
const AttestationPath = apiPath + "/webauthn/attestation"

const AssertionPath = apiPath + "/webauthn/assertion"

const AdminPath = apiPath + "/admin"

func UpdConsts() {
	MacExpirePollTime = toInt(os.Getenv("MAC_EXPIRE_POLL_TIME"))
	CookieLifeTime = toInt(os.Getenv("COOKIE_LIFETIME"))
	MacUserLifetime = int64(toInt(os.Getenv("RADCHECK_LIFETIME")))
	CookieDomain = os.Getenv("COOKIE_DOMAIN")
}
