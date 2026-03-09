package outbound

type PasswordBlockListPort interface {
	isInPasswordsBlocklist(password string) (bool, error)
}
