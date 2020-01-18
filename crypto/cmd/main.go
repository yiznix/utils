package main

import (
	"flag"
	"fmt"

	"github.com/yiznix/utils/crypto"
)

const pepper = "12345678901234567890123456"

var passwd = flag.String("password", "hello", "")

func main() {
	flag.Parse()
	hashedPwd, err := crypto.HashPassword(*passwd, pepper)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Password: %s, Hashed password: %s\n", *passwd, hashedPwd)
}
