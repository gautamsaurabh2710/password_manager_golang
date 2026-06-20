package mailer

import (
	"fmt"

	"gopkg.in/gomail.v2"
)

func SendOTP(email, otp, user, pass string) error {

	//fmt.Println("EMAIL_USER:", user)
    //fmt.Println("EMAIL_PASS_SET:", pass != "")
	//if user == "" || pass == "" {
	//	return fmt.Errorf("missing EMAIL_USER/EMAIL_PASS")
	//}

	//message := gomail.NewMessage()
	//message.SetHeader("From", user)
	//message.SetHeader("To", email)
	//message.SetHeader("Subject", "OTP Verification")
	//message.SetBody("text/plain", fmt.Sprintf("Your OTP is %s", otp))

	//dialer := gomail.NewDialer("smtp.gmail.com", 587, user, pass)
	//return dialer.DialAndSend(message)

	fmt.Println("OTP:", otp)
	return nil
}
