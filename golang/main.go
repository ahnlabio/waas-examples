package main

import (
	"fmt"

	"github.com/ahnlabio/waas-example.git/golang/signup"
)

func main() {
	fmt.Println("==========start waas docs scenario==========")
	// securechannel.SecureChannelScenario()
	signup.SignupScenario()
	fmt.Println("==========end waas docs scenario==========")
}
