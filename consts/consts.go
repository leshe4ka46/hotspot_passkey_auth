package consts

const MacUserLifetime = 1 //min

const DistPath = "/home/alex/go-webauthn-example/front/build/"

const CookieLifeTime = 3600
const LoginCookieName = "loginCookie"
const CookieDomain = "localhost"
const SecureCookie = false

const apiPath = "/api"
const LoginPath = apiPath + "/login"
const LogoutPath = apiPath + "/logout"

const InfoPath = apiPath + "/info"
const LoginWithoutKeysPath = apiPath + "/radius/login"
const AttestationPath = apiPath + "/webauthn/attestation"

const AssertionPath = apiPath + "/webauthn/assertion"