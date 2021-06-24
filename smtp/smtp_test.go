package smtp

import "testing"

func TestSend(t *testing.T) {
	email := NewEmail("smtp.gmail.com", "587", "xzhang@yiznix.com", "Blu1mo0nxxjjzz8a", "test sending email from go code 2", "test", "xzhang@yiznix.com", []string{"yiznix@gmail.com"})
	err := email.Send()
	if err != nil {
		t.Fatal(err)
	}
}
