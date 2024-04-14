package wa

import (
	"net/url"
	"github.com/go-webauthn/webauthn/protocol"
)

type Config struct {
	ExternalURL url.URL
	DisplayName string
	RPID        string

	UserVerification        protocol.UserVerificationRequirement
	AuthenticatorAttachment protocol.AuthenticatorAttachment
	ConveyancePreference    protocol.ConveyancePreference
}

func (c Config) AuthenticatorSelection(requirement protocol.ResidentKeyRequirement) (selection protocol.AuthenticatorSelection) {
	selection = protocol.AuthenticatorSelection{
		AuthenticatorAttachment: c.AuthenticatorAttachment,
		UserVerification:        c.UserVerification,
		ResidentKey:             requirement,
	}

	if selection.ResidentKey == "" {
		selection.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
	}

	switch selection.ResidentKey {
	case protocol.ResidentKeyRequirementRequired:
		selection.RequireResidentKey = protocol.ResidentKeyRequired()
	case protocol.ResidentKeyRequirementDiscouraged:
		selection.RequireResidentKey = protocol.ResidentKeyNotRequired()
	}

	if selection.AuthenticatorAttachment == "" {
		selection.AuthenticatorAttachment = protocol.CrossPlatform
	}

	if selection.UserVerification == "" {
		selection.UserVerification = protocol.VerificationPreferred
	}

	return selection
}
