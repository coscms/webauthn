package main

import (
	"encoding/gob"
	"fmt"
	"time"

	cw "github.com/coscms/webauthn"
	"github.com/coscms/webauthn/static"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/webx-top/echo"
	"github.com/webx-top/echo/defaults"
	"github.com/webx-top/echo/engine"
	"github.com/webx-top/echo/engine/standard"
	"github.com/webx-top/echo/handler/embed"
	"github.com/webx-top/echo/middleware/session"
)

func init() {
	gob.Register(&webauthn.SessionData{})
}

func main() {
	w := cw.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",          // Display Name for your site
		RPID:          "localhost",             // Generally the domain name for your site
		RPOrigin:      "http://localhost:4444", // The origin URL for WebAuthn requests
		RPIcon:        icon,                    // Optional icon URL for your site
	}, &userHandle{})
	if err := w.Init(); err != nil {
		panic(err)
	}
	defaults.Use(session.Middleware(echo.DefaultSessionOptions))
	w.RegisterRoute(defaults.Default)
	fs := embed.NewFileSystems()
	fs.Register(static.HTML)
	fs.Register(static.JS)
	defaults.Get(`/`, func(c echo.Context) error {
		return c.Redirect(`/static/index.html`)
	})
	defaults.Get(`/static/*`, embed.File(fs))
	cfg := &engine.Config{
		Address: `:4444`,
	}
	fmt.Println(`visit URL: http://localhost:4444/`)
	defaults.Run(standard.NewWithConfig(cfg))
}

var icon = "https://www.coscms.com/public/assets/backend/images/logo.png"
var defaultUser = &user{
	id:          100,
	name:        `exampleUser@coscms.com`,
	displayName: `exampleUser`,
	icon:        icon,
}

type userHandle struct {
}

func (u *userHandle) GetUser(ctx echo.Context, username string, opType cw.Type, stage cw.Stage) (webauthn.User, error) {
	user := defaultUser
	if username != user.name {
		return nil, fmt.Errorf("username mismatch")
	}
	return user, nil
}

func (u *userHandle) Register(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error {
	defaultUser.credentials = append(defaultUser.credentials, *cred)
	return nil
}

func (u *userHandle) Login(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error {
	fmt.Println(`Login Success:`, time.Now().Format(time.RFC3339))
	return nil
}

type user struct {
	id          uint64
	name        string
	displayName string
	icon        string
	credentials []webauthn.Credential
}

// User ID according to the Relying Party
func (u *user) WebAuthnID() []byte {
	return cw.WebAuthnID(u.id)
}

// User Name according to the Relying Party
func (u *user) WebAuthnName() string {
	return u.name
}

// Display Name of the user
func (u *user) WebAuthnDisplayName() string {
	return u.displayName
}

// User's icon url
func (u *user) WebAuthnIcon() string {
	return u.icon
}

// Credentials owned by the user
func (u *user) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
