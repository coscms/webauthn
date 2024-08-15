package webauthn

import (
	"encoding/binary"

	"github.com/webx-top/echo"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type UserHandler interface {
	GetUser(ctx echo.Context, username string, opType Type, stage Stage) (webauthn.User, error)
	Register(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error
	Login(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error
	Unbind(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error
}

func makeCredentialDescriptorList(_ echo.Context, user webauthn.User) []protocol.CredentialDescriptor {
	list := user.WebAuthnCredentials()
	credentialDescList := make([]protocol.CredentialDescriptor, 0, len(list))
	for _, cred := range list {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialDescList = append(credentialDescList, descriptor)
	}
	return credentialDescList
}

func SetConfigDefaults(c *webauthn.Config) {
	if len(c.AuthenticatorSelection.UserVerification) == 0 {
		c.AuthenticatorSelection.UserVerification = protocol.VerificationDiscouraged // 登录时不用输入pin码
	}
	if len(c.AttestationPreference) == 0 {
		c.AttestationPreference = protocol.PreferDirectAttestation
	}
}

func WebAuthnID(uid uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(uid))
	return buf
}
