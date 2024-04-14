package wa

import (
	"encoding/json"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func InitWebauthn(cfg Config) (wa *webauthn.WebAuthn, err error) {
	wa, err = webauthn.New(&webauthn.Config{
		RPID:                  cfg.ExternalURL.Hostname(),
		RPDisplayName:         cfg.DisplayName,
		RPOrigin:              cfg.ExternalURL.String(),
		AttestationPreference: cfg.ConveyancePreference,
		Timeout:               60000,
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
