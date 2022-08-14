package webauthn

import (
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/webx-top/echo"
)

func New(cfg *webauthn.Config, user UserHandler) *Server {
	a := &Server{
		config: cfg,
		user:   user,
	}
	return a
}

type Server struct {
	config   *webauthn.Config
	webAuthn *webauthn.WebAuthn
	user     UserHandler
}

func (s *Server) Init() error {
	var err error
	s.webAuthn, err = webauthn.New(s.config)
	return err
}

func (s *Server) RegisterRoute(r echo.RouteRegister) {

	g := r.Group(`/webauthn`)
	g.Get("/register/begin/:username", s.handleBeginRegistration).SetName(`webauthn.beginRegister`)
	g.Post("/register/finish/:username", s.handleFinishRegistration).SetName(`webauthn.finishRegister`)
	g.Get("/login/begin/:username", s.handleBeginLogin).SetName(`webauthn.beginLogin`)
	g.Post("/login/finish/:username", s.handleFinishLogin).SetName(`webauthn.finishLogin`)

}

func (s *Server) handleBeginRegistration(ctx echo.Context) error {

	// get username/friendly name
	username := ctx.Param("username")

	// get user
	user, err := s.user.GetUser(ctx, username, TypeRegister, StageBegin)
	if err != nil {
		return err
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = credentialExcludeList(ctx, s.user, user)
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		return err
	}

	ctx.Session().Set(sessionKeyRegister, sessionData)

	return ctx.JSON(options)
}

func (s *Server) handleFinishRegistration(ctx echo.Context) error {

	// get username
	username := ctx.Param("username")

	// get user
	user, err := s.user.GetUser(ctx, username, TypeRegister, StageFinish)
	if err != nil {
		return err
	}

	// load the session data
	sessionData, ok := ctx.Session().Get(sessionKeyRegister).(*webauthn.SessionData)
	if !ok {
		return echo.ErrBadRequest
	}

	credential, err := s.webAuthn.FinishRegistration(user, *sessionData, ctx.Request().StdRequest())
	if err != nil {
		return err
	}

	err = s.user.AddCredential(ctx, user, credential)
	if err != nil {
		return err
	}

	ctx.Session().Delete(sessionKeyRegister)

	return ctx.JSON("Registration Success")
}

func (s *Server) handleBeginLogin(ctx echo.Context) error {

	// get username
	username := ctx.Param("username")

	// get user
	user, err := s.user.GetUser(ctx, username, TypeLogin, StageBegin)
	if err != nil {
		return err
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return err
	}

	// store session data as marshaled JSON
	ctx.Session().Set(sessionKeyLogin, sessionData)

	return ctx.JSON(options)
}

func (s *Server) handleFinishLogin(ctx echo.Context) error {

	// get username
	username := ctx.Param("username")

	// get user
	user, err := s.user.GetUser(ctx, username, TypeLogin, StageFinish)
	if err != nil {
		return err
	}

	// load the session data
	sessionData, ok := ctx.Session().Get(sessionKeyLogin).(*webauthn.SessionData)
	if !ok {
		return echo.ErrBadRequest
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = s.webAuthn.FinishLogin(user, *sessionData, ctx.Request().StdRequest())
	if err != nil {
		return err
	}

	// handle successful login
	err = s.user.LoginSuccess(ctx, user)
	if err != nil {
		return err
	}

	ctx.Session().Delete(sessionKeyLogin)

	return ctx.JSON("Login Success")
}
