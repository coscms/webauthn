package webauthn

import (
	"encoding/binary"

	"github.com/webx-top/echo"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

type UserHandler interface {
	GetUser(ctx echo.Context, username string, opType Type, stage Stage) (webauthn.User, error)
	AddCredential(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error
	WebAuthnCredentials(ctx echo.Context, user webauthn.User) []webauthn.Credential
	LoginSuccess(ctx echo.Context, user webauthn.User) error
}

func credentialExcludeList(ctx echo.Context, u UserHandler, user webauthn.User) []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.WebAuthnCredentials(ctx, user) {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

func WebAuthnID(uid uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(uid))
	return buf
}
