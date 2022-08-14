package webauthn

type Type int
type Stage int

const (
	TypeLogin Type = iota + 1
	TypeRegister
)

const (
	StageBegin Stage = iota + 1
	StageFinish
)

const (
	sessionKeyRegister = `webauthn.registration`
	sessionKeyLogin    = `webauthn.authentication`
)
