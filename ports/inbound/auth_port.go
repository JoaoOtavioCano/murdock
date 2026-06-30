package inbound

import "github.com/JoaoOtavioCano/murdock/ports/inbound/commands"

type AuthPort interface {
	Signup(cmd commands.SignupCmd) error
	Login(cmd commands.LoginCmd) ([]byte, error)
	CheckSessionStatus(cmd commands.CheckSessionStatusCmd) error
	Delete(cmd commands.DeleteCmd) error
	ConfirmationCodeValidation(digitalAdd, code string) error
	ChangePasswordRequest(cmd commands.ChangePasswordRequestCmdEmailPasswordMethod) error
}
