package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"

func isExistUser(email string) bool {
	/*
	   주어진 사용자 이메일이 이미 가입된 사용자 인지 확인합니다.

	   Args:
	       email (str): 확인할 사용자의 이메일 주소.

	   Returns:
	       bool: 이미 존재하는 계정인 경우 True, 가입되지 않은 계정인 경우 False.

	   Raises:
	       HTTPError: 요청이 실패한 경우.

	   Note:
	       이미 가입된 이메일인 경우, 서버는 상태 코드 400과 함께 다음과 같은 응답을 반환합니다:
	       {
	           "code": 606,
	           "msg": "Email is already in use.",
	           "object": null,
	           "errorResponse": "{\"code\":606,\"msg\":\"Email is already in use.\"}"
	       }
	*/

	waas_base_url, isExistEnv := os.LookupEnv("WAAS_BASE_URL")
	if !isExistEnv {
		waas_base_url = WAAS_BASE_URL
	}

	url := fmt.Sprintf("%s/member/user-management/users/%s?serviceid=https://mw.myabcwallet.com", waas_base_url, email)

	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return res.StatusCode != http.StatusOK
}
