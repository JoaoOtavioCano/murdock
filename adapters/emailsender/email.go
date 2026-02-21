package emailsender

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"os"
)

type EmailServices struct {
	smtpServerAddr string
	port           string
	auth           auth
	from           string
	to             []string
	subject        string
	contentType    string
	body           string
}

type auth struct {
	username string
	password string
}

const (
	contentTypeHTML = "Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n"
)

//go:embed templates/confirmationCode.html
var f embed.FS

func NewEmailServices() *EmailServices {
	return &EmailServices{
		smtpServerAddr: "smtp.gmail.com",
		port:           "587",
		auth: auth{
			username: os.Getenv("EMAIL_USERNAME"),
			password: os.Getenv("EMAIL_PASSWORD"),
		},
		from: os.Getenv("EMAIL_USERNAME"),
	}
}

func (s *EmailServices) send() error {
	auth := smtp.PlainAuth("", s.auth.username, s.auth.password, s.smtpServerAddr)

	msg := []byte(fmt.Sprintf("To: %s\r\n", s.to[0]))
	msg = append(msg, []byte(fmt.Sprintf("Subject: %s\r\n", s.subject))...)
	msg = append(msg, []byte(contentTypeHTML)...)
	msg = append(msg, []byte(s.body)...)

	err := smtp.SendMail(s.smtpServerAddr+":"+s.port, auth, s.from, s.to, msg)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func (s *EmailServices) SendConfirmationCode(address string, msg []byte, code string) error {
	tmpl, err := template.ParseFS(f, "templates/confirmationCode.html")
	if err != nil {
		log.Println("[parse template error] - " + err.Error())
		return err
	}
	var buf bytes.Buffer

	data := struct {
		Msg  string
		Code string
	}{
		Msg:  string(msg),
		Code: code,
	}

	err = tmpl.Execute(&buf, data)
	if err != nil {
		log.Println(err)
		return err
	}

	s.body = buf.String()

	s.subject = "Email verificatrion"

	s.to = append(s.to, address)

	err = s.send()
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func (s *EmailServices) SendNotification(address string, msg []byte) error {
	return nil
}
