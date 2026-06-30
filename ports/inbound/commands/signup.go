package commands

type SignupCmd interface {
	isSignupCmd()
}

type SignupCmdEmailPasswordMethod struct {
	Email    string
	Password string
}

func (SignupCmdEmailPasswordMethod) isSignupCmd() {}
