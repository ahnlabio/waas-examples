"""signup.py - WAAS 회원 가입 API 사용 예제"""

import base64
import http
import os
from typing import Literal

import requests

import securechannel  # (1)

WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"


def is_exist_user(email: str) -> bool:
    """
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
    """

    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.get(
        url=f"{waas_base_url}/member/user-management/users/{email}?serviceid=https://mw.myabcwallet.com"
    )
    return r.status_code != http.HTTPStatus.OK


def register_email_user(
    email: str,
    encrypted_password: str,
    verification_code: str,
    channel_id: str,
    auth: str,
    overage: Literal[0, 1],
    agree: Literal[0, 1],
    collect: Literal[0, 1],
    third_party: Literal[0, 1],
    advertise: Literal[0, 1],
):
    """
    회원 가입

    성공시 오류 없이 종료

    Args:
        email (str): 사용자 이메일
        encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
        verification_code (str): 인증 코드. 이메일로 전송된 인증 코드를 입력합니다.
        channel_id (str): 보안 채널 ID.  # (2)
        auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.
        overage (int): 14세 이상 사용자 동의
        agree (int): 서비스 이용 약관 동의
        collect (int): 개인정보 수집 및 이용 동의
        third_party (int): 제3자 정보 제공 동의
        advertise (int): 광고성 정보 수신 동의
    """
    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.post(
        url=f"{waas_base_url}/member/user-management/users/v2/adduser",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {auth}",
            "Secure-Channel": channel_id,
        },
        data={
            "username": email,
            "password": encrypted_password,
            "code": verification_code,
            "overage": overage,
            "agree": agree,
            "collect": collect,
            "third_party": third_party,
            "advertise": advertise,
            "serviceid": "https://mw.myabcwallet.com",
        },
    )
    r.raise_for_status()


def send_verification_code(email: str, lang: Literal["ko", "en", "ja"] = "en"):
    """
    사용자 이메일로 인증 코드를 전송합니다.

    성공하면 함수는 오류 없이 종료

    Args:
        email (str): 인증 코드를 전송할 사용자의 이메일 주소.
        lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

    Raises:
        HTTPError: 요청이 실패한 경우.

    """
    send_code(email, lang, "verify")


def send_auth_code(email: str, lang: Literal["ko", "en", "ja"] = "en"):
    """
    사용자 이메일로 패스워드 변경 인증 코드를 전송합니다.

    성공하면 함수는 오류 없이 종료

    Args:
        email (str): 인증 코드를 전송할 사용자의 이메일 주소.
        lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

    Raises:
        HTTPError: 요청이 실패한 경우.
    """
    send_code(email, lang, "changepassword")


def send_password_reset_code(email: str, lang: Literal["ko", "en", "ja"] = "en"):
    """
    사용자 이메일로 패스워드 초기화 인증 코드를 전송합니다.

    성공하면 함수는 오류 없이 종료

    Args:
        email (str): 인증 코드를 전송할 사용자의 이메일 주소.
        lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

    Raises:
        HTTPError: 요청이 실패한 경우.
    """

    send_code(email, lang, "initpassword")


def verify_code(email: str, code: str) -> bool:
    """
    사용자가 입력한 코드가 올바른지 확인합니다.

    send_verification_code, send_auth_code, send_password_reset_code 함수로 전송된 코드를 확인합니다.

    Args:
        email (str): 사용자 이메일 주소.
        code (str): 사용자가 입력한 코드.

    Returns:
        bool: 사용자가 입력한 코드가 올바른 경우 True, 그렇지 않은 경우 False.

    Raises:
        HTTPError: 요청이 실패한 경우.
    """
    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.post(
        url=f"{waas_base_url}/member/mail-service/{email}/verifycode",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"code": code, "serviceid": "https://mw.myabcwallet.com"},
    )
    return r.status_code == http.HTTPStatus.OK


def send_code(
    email: str,
    lang: Literal["ko", "en", "ja"],
    template: Literal["verify", "changepassword", "initpassword"],
):
    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    params = {"lang": lang, "template": template}
    r = requests.get(
        url=f"{waas_base_url}/member/mail-service/{email}/sendcode",
        params=params,
    )
    r.raise_for_status()


def main():
    email = "email"  # 사용자 이메일
    password = "password"  # 사용자 비밀번호
    client_id = "Client ID"  # 발급받은 Client ID
    client_secret = "Client Secret"  # 발급받은 Client Secret
    verification_code = "verification code"  # 사용자가 입력한 인증 코드

    # 이미 가입된 사용자인지 확인합니다.
    if is_exist_user(email):
        print(f"{email} is already exist")
        return

    print(f"{email} is not exist")

    # 이메일로 인증 코드를 전송합니다.
    send_verification_code(email)
    print("verification code sent")

    # 사용자가 입력한 인증 코드가 올바른지 확인합니다.
    # 인증코드를 발송한 다음 사용자로부터 verification_code 를 입력 받습니다.
    if not verify_code(email, verification_code):
        print("Invalid code")
        return

    # 사용자의 비밀번호를 암호화합니다.
    secure_channel = securechannel.create_secure_channel()
    encrypted_password = securechannel.encrypt(secure_channel, password)

    # 사용자의 동의를 받습니다.
    overage = 1
    agree = 1
    collect = 1
    third_party = 1
    advertise = 1

    # Client ID / Client Secret
    auth = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode(
        "utf-8"
    )  # (3)

    # 사용자를 등록합니다.
    register_email_user(
        email,
        encrypted_password,
        verification_code,
        channel_id=secure_channel["channel_id"],
        auth=auth,
        overage=overage,
        agree=agree,
        collect=collect,
        third_party=third_party,
        advertise=advertise,
    )
    print("signup success")

    exist_result = is_exist_user(email)
    print(f"{email} is exist: {exist_result}")


if __name__ == "__main__":
    main()


"""
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
2.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
3.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
"""
