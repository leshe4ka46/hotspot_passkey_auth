package consts

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

const DistPath = "/auth-files/"

func toInt(s string) (i int) {
	i, _ = strconv.Atoi(s)
	return
}

func toBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes", "y":
		return true, nil
	case "0", "false", "f", "no", "n":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean string: %s", s)
	}
}

var MacExpirePollTime = 60 * 60

var CookieLifeTime = 60 * 60

var MacUserLifetime int64 = 60 * 60

const LoginCookieName = "loginCookie"

var CookieDomain = ""

const SecureCookie = false

const apiPath = "/api"
const LoginPath = apiPath + "/login"
const LogoutPath = apiPath + "/logout"

const InfoPath = apiPath + "/info"
const LoginWithoutKeysPath = apiPath + "/radius/login"
const AttestationPath = apiPath + "/webauthn/attestation"

const AssertionPath = apiPath + "/webauthn/assertion"

const AdminPath = apiPath + "/admin"

var ReleaseBuild = false

func UpdConsts() {
	if tmp := os.Getenv("DOCKER_RELEASE"); tmp != "" {
		releaseBuild, err := toBool(tmp)
		if err != nil {
			log.Fatal(err)
		}
		ReleaseBuild = releaseBuild
	}
	if tmp := os.Getenv("MAC_EXPIRE_POLL_TIME"); tmp != "" {
		MacExpirePollTime = toInt(tmp)
	}
	if tmp := os.Getenv("COOKIE_LIFETIME"); tmp != "" {
		CookieLifeTime = toInt(tmp)
	}
	if tmp := os.Getenv("RADCHECK_LIFETIME"); tmp != "" {
		MacUserLifetime = int64(toInt(tmp))
	}
	if tmp := os.Getenv("COOKIE_DOMAIN"); tmp != "" {
		CookieDomain = tmp
	} else {
		log.Fatal("env param COOKIE_DOMAIN is not set")
	}
}
