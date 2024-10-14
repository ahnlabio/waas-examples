package main

import (
	"fmt"

	"github.com/ahnlabio/waas-example.git/golang/login"
)

func main() {
	fmt.Println("==========start waas docs scenario==========")
	// securechannel.SecureChannelScenario()
	// signup.SignupScenario()
	login.LoginScenario()
	fmt.Println("==========end waas docs scenario==========")
}
