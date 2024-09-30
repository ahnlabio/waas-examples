"""login.py - WAAS 로그인 API 사용 예제"""

import os
import base64
from typing import TypedDict, List
from urllib.parse import urlparse

import jwt  # pip install pyjwt
import requests  # pip install requests

import securechannel  # (1)

WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"

EmailLoginResultDict = TypedDict(
    "EmailLoginResultDict",
    {
        "access_token": str,
        "refresh_token": str,
        "token_type": str,
        "expire_in": int,
    },
)

DecodedToken = TypedDict(
    "DecodedToken",
    {
        "sub": str,
        "aud": str,
        "iss": str,
        "pid": str,
        "exp": int,
        "iat": int,
        "jti": str,
        "user-agent": str,
    },
)

JWKKey = TypedDict(
    "JWKKey",
    {
        "kty": str,
        "use": str,
        "crv": str,
        "kid": str,
        "x": str,
        "y": str,
        "alg": str,
    },
)

JWKDict = TypedDict(
    "JWKDict",
    {
        "keys": List[JWKKey],
    },
)

JWTHeader = TypedDict(
    "JWTHeader",
    {
        "alg": str,
        "typ": str,
        "kid": str,
    },
)


def email_login(
    email: str, encrypted_password: str, secure_channel_id: str, auth: str
) -> EmailLoginResultDict:
    """
    이메일과 암호를 사용하여 로그인 요청을 보냅니다.

    Args:
        email (str): 사용자의 이메일 주소.
        encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
        secure_channel_id (str): 보안 채널 ID.
        auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

    Returns:
        EmailLoginResultDict: 로그인 요청에 대한 서버의 응답.

    Raises:
        HTTPError: 로그인 요청이 실패한 경우.
    """

    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.post(
        url=f"{waas_base_url}/auth/auth-service/v2/login",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Secure-Channel": secure_channel_id,
            "Authorization": f"Basic {auth}",
        },
        data={
            "grant_type": "password",
            "username": email,
            "password": encrypted_password,
            "audience": "https://mw.myabcwallet.com",
        },
    )

    r.raise_for_status()
    return r.json()


def refresh_token(refresh_token: str, auth: str) -> EmailLoginResultDict:
    """
    refresh token 을 사용하여 access token 을 재발급합니다.

    Args:
        refresh_token (str): refresh token.
        auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

    Returns:
        EmailLoginResultDict: 재발급된 access token.
    """

    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.post(
        url=f"{waas_base_url}/auth/auth-service/v2/refresh",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {auth}",
        },
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
    )
    r.raise_for_status()
    return r.json()


def verify_token(token: str) -> bool:
    """
    Token 을 검증합니다.

    1. Token 으로부터 user_pool_id 를 추출합니다.
    2. user_pool_id 를 사용하여 JWK 목록을 불러옵니다.
    3. Token header 의 kid 값과 일치하는 JWK 를 찾아 token 을 검증합니다.

    jwks.json example:
    >>> {
        "keys": [
            {
                "kty": "EC",
                "use": "sig",
                "crv": "P-256",
                "kid": "0",
                "x": "ZrVThPhiQSQw1YQcuXjD1qm2stKQty2N1L8gnWDVtzU",
                "y": "B6nqJgdH00TIPJkINiT6JzfDfteKVLYtP0x3NuaCpbY",
                "alg": "ES256",
            }
        ]
    }

    decoded_token data example:
    >>> {
        "sub": "85abcd789a0749e0b8de39226c05f81c",
        "aud": "https://mw.myabcwallet.com",
        "iss": "https://dev-api.id.myabcwallet.com/266021e24dd0bfaaa96f2b5e21d7c800",
        "pid": "5babdf06-2a5c-4d17-88f5-2998a3db7e21",
        "exp": 1727416466,
        "iat": 1727415866,
        "jti": "bc5c7a5f29684063bdd332b9262d1c7b",
        "user-agent": "python-requests/2.32.3",
    }

    Args:
        token (str): 검증할 JWT token.

    Returns:
        bool: 검증 결과.
    """
    decoded_token: DecodedToken = jwt.decode(token, options={"verify_signature": False})
    user_pool_id = urlparse(decoded_token["iss"]).path[1:]

    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.get(
        f"{waas_base_url}/jwk/key-service/{user_pool_id}/.well-known/jwks.json",
    )
    r.raise_for_status()
    jwks: JWKDict = r.json()

    jwt_header = jwt.get_unverified_header(token)
    # kid 가 일치하는 첫번째 항목을 찾는다. 존재하는 경우 검증 성공.
    k = next(filter(lambda k: k["kid"] == jwt_header["kid"], jwks["keys"]), False)
    return bool(k)


def main():
    email = "email"  # 사용자 이메일
    password = "password"  # 사용자 비밀번호
    client_id = "Client ID"  # 발급받은 Client ID
    client_secret = "Client Secret"  # 발급받은 Client Secret

    # Secure Channel 생성
    secure_channel = securechannel.create_secure_channel()

    # password 는 Secure Channel 암호화가 필요합니다
    encrypted_password = securechannel.encrypt(secure_channel, password)

    # Client ID / Client Secret
    auth = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode(
        "utf-8"
    )  # (2)

    # 로그인
    email_login_result = email_login(
        email,
        encrypted_password,
        secure_channel["channel_id"],
        auth,
    )

    # 성공 시 jwt token 생성됨
    print(f"access_token: {email_login_result['access_token']}")
    print(f"refresh_token: {email_login_result['refresh_token']}")

    # jwt token 검증
    verify_result = verify_token(email_login_result["access_token"])
    print(f"verify_result: {verify_result}")

    refresh_token_result = refresh_token(
        email_login_result["refresh_token"],
        auth,
    )

    # 성공 시 jwt token 재발급됨
    print(f"access_token: {refresh_token_result['access_token']}")
    print(f"refresh_token: {refresh_token_result['refresh_token']}")

    # jwt token 검증
    verify_result = verify_token(email_login_result["access_token"])
    print(f"verify_result: {verify_result}")


if __name__ == "__main__":
    main()

"""
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
2.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
"""
