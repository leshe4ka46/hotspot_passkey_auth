package consts

import "os"

const MacUserLifetime = 1 //min

const DistPath = "/home/alex/go-webauthn-example/front/build/"

var CookieLifeTime = os.Getenv("COOKIE_LIFETIME")
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