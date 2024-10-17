package main

import (
	"fmt"

	"github.com/ahnlabio/waas-example.git/golang/login"
	"github.com/ahnlabio/waas-example.git/golang/mpc"
	securechannel "github.com/ahnlabio/waas-example.git/golang/secureChannel"
	"github.com/ahnlabio/waas-example.git/golang/signup"
)

func main() {
	fmt.Println("==========start waas docs scenario==========")
	securechannel.SecureChannelScenario()
	signup.SignupScenario()
	login.LoginScenario()
	mpc.MPCScenario()
	fmt.Println("==========end waas docs scenario==========")
}
