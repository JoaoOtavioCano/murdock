package commands

type CheckSessionStatusCmd interface {
	isCheckSessionStatusCmd()
	GetToken() string
}

type CheckSessionStatusCmdEmailPasswordMethod struct {
	token string
}

func (CheckSessionStatusCmdEmailPasswordMethod) isCheckSessionStatusCmd() {}
func NewCheckSessionStatusCmdEmailPasswordMethod(token string) CheckSessionStatusCmdEmailPasswordMethod {
	return CheckSessionStatusCmdEmailPasswordMethod{token: token}
}

func (cmd CheckSessionStatusCmdEmailPasswordMethod) GetToken() string {
	return cmd.token
}
