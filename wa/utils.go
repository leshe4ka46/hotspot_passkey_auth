package wa

import (
	"encoding/json"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"time"
)

func InitWebauthn(cfg Config) (wa *webauthn.WebAuthn, err error) {
	wa, err = webauthn.New(&webauthn.Config{
		RPID:                  cfg.ExternalURL.Hostname(),
		RPDisplayName:         cfg.DisplayName,
		RPOrigins:             []string{cfg.ExternalURL.String()},
		AttestationPreference: cfg.ConveyancePreference,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,             // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for login sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,             // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for registration sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
			},
		},
	})
	return
}

func ParceAttestationPreference(pref string) protocol.ConveyancePreference {
	if pref == "indirect" {
		return protocol.PreferIndirectAttestation
	}
	if pref == "direct" {
		return protocol.PreferDirectAttestation
	}
	return protocol.PreferNoAttestation
}

func JSONString(obj interface{}) string {
	bytes, _ := json.Marshal(obj)
	return string(bytes)
}
