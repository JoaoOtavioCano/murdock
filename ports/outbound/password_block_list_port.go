package outbound

type PasswordBlockListPort interface {
	IsInPasswordsBlocklist(password string) (bool, error)
}
