package main

import (
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

func main() {
	w := cw.New(&userHandle{})
	if err := w.Init(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",          // Display Name for your site
		RPID:          "localhost",             // Generally the domain name for your site
		RPOrigin:      "http://localhost:4444", // The origin URL for WebAuthn requests
		RPIcon:        icon,                    // Optional icon URL for your site
	}); err != nil {
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
var defaultUser = &cw.User{
	ID:          100,
	Name:        `exampleUser@coscms.com`,
	DisplayName: `exampleUser`,
	Icon:        icon,
}

type userHandle struct {
}

func (u *userHandle) GetUser(ctx echo.Context, username string, opType cw.Type, stage cw.Stage) (webauthn.User, error) {
	user := defaultUser
	if username != user.Name {
		return nil, fmt.Errorf("username mismatch")
	}
	return user, nil
}

func (u *userHandle) Register(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error {
	defaultUser.Credentials = append(defaultUser.Credentials, *cred)
	return nil
}

func (u *userHandle) Login(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error {
	fmt.Println(`Login Success:`, time.Now().Format(time.RFC3339))
	return nil
}

func (u *userHandle) Unbind(ctx echo.Context, user webauthn.User, cred *webauthn.Credential) error {
	fmt.Println(`Unbind Success:`, time.Now().Format(time.RFC3339))
	return nil
}
