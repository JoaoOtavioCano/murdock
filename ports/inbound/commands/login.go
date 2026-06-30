package commands

type LoginCmd interface {
	isLoginCmd()
}

type LoginCmdEmailPasswordMethod struct {
	Email    string
	Password string
}

func (LoginCmdEmailPasswordMethod) isLoginCmd() {}
