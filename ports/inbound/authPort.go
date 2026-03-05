package inbound

type AuthPort interface {
	Signup(r AuthReq) error
	Login(r AuthReq) ([]byte, error)
	Check(r AuthReq) error
	Delete(r AuthReq) error
	ConfirmationCodeValidation(digitalAdd, code string) error
}

type AuthReq struct {
	Method string            `json:"method"`
	Data   map[string]string `json:"data"`
}
