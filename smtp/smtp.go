// Use of this source code is governed by the license that can be found in LICENSE file.

package smtp

import (
	"fmt"
	"net/smtp"
	"strings"
)

var (
	emailBody = "To: %s\r\nSubject: %s\r\n\r\n%s\r\n"
)

// Email represents an Email.
type Email struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
	Subject  string
	Message  string
	To       []string
}

// NewEmail creates a new Email.
func NewEmail(h, p, user, pwd, subject, msg, from string, to []string) *Email {
	return &Email{
		Host:     h,
		Port:     p,
		User:     user,
		Password: pwd,
		From:     from,
		To:       to,
		Subject:  subject,
		Message:  msg,
	}
}

// Send sends out the email.
// This needs to turn on "Less secure apps" option in gmail account.
func (e *Email) Send() error {
	auth := smtp.PlainAuth("", e.User, e.Password, e.Host)
	body := fmt.Sprintf(emailBody, strings.Join(e.To, ","),
		e.Subject, e.Message)
	return smtp.SendMail(e.Host+":"+e.Port, auth, e.From, e.To, []byte(body))
}
