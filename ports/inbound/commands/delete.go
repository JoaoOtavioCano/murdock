package commands

type DeleteCmd interface {
	isDeleteCmd()
	GetToken() string
	ToCheckSessionStatusCmd() CheckSessionStatusCmd
}

type DeleteCmdEmailPasswordMethod struct {
	token string
}

func NewDeleteCmdEmailPasswordMethod(token string) DeleteCmdEmailPasswordMethod {
	return DeleteCmdEmailPasswordMethod{token: token}
}

func (cmd DeleteCmdEmailPasswordMethod) GetToken() string {
	return cmd.token
}

func (cmd DeleteCmdEmailPasswordMethod) ToCheckSessionStatusCmd() CheckSessionStatusCmd {
	return NewCheckSessionStatusCmdEmailPasswordMethod(cmd.token)
}

func (DeleteCmdEmailPasswordMethod) isDeleteCmd() {}
