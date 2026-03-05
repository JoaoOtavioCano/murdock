package errors

type ValidationError struct {
	msg string
}

func (e ValidationError) Error() string {
	if e.msg == "" {
		e.msg = "validatio error"
	}
	return e.msg
}

type UserLockedError struct{}

func (e UserLockedError) Error() string {
	return "user is locked"
}

type EmptyEmailError struct{}

func (e EmptyEmailError) Error() string {
	return "empty email"
}

type UserAlreadyExistsError struct{}

func (e UserAlreadyExistsError) Error() string {
	return "user already exists"
}

type NotAbleToEncryptPasswordError struct{}

func (e NotAbleToEncryptPasswordError) Error() string {
	return "not able to encrypt password"
}

type NotAbleToIssueJWTError struct{}

func (e NotAbleToIssueJWTError) Error() string {
	return "not able to issue JWT"
}

type EmptyPasswordError struct{}

func (e EmptyPasswordError) Error() string {
	return "empty password"
}

type FoundInBlocklistError struct{}

func (e FoundInBlocklistError) Error() string {
	return "password found in blocklist"
}

type UserNotFoundError struct{}

func (e UserNotFoundError) Error() string {
	return "user not found"
}

type WrongPasswordError struct{}

func (e WrongPasswordError) Error() string {
	return "wrong password"
}

type UserExceededMaxNumOfAttemptsError struct{}

func (e UserExceededMaxNumOfAttemptsError) Error() string {
	return "user locked because too many login attempts failed"
}

type ConfirmationCodeExpiredError struct{}

func (e ConfirmationCodeExpiredError) Error() string {
	return "code expired"
}
