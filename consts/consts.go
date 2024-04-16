package consts

import (
	"os"
	"strconv"
)

const DistPath = "./dist"

func toInt(s string) (i int) {
	i, _ = strconv.Atoi(s)
	return
}

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
