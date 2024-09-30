"""mpc.py - WAAS 지갑 생성/복구 API 사용 예제"""

import base64
import os
from typing import TypedDict, List

import requests

import securechannel  # (1)
import login  # (2)

WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"

WalletAccount = TypedDict(
    "WalletAccount",
    {
        "id": str,
        "sid": str,
        "ethAddress": str,
        "icon": str,
        "name": str,
        "signer": str,
        "pubkey": str,
    },
)


WalletInfo = TypedDict(
    "WalletInfo",
    {
        "_id": str,
        "uid": str,
        "wid": int,
        "email": str,
        "accounts": List[WalletAccount],
        "favorites": List,
        "autoconfirms": List,
        "twoFactorEnabled": bool,
        "twoFactorResetRetryCount": int,
        "twoFactorRetryFreezeEndTime": int,
        "twoFactorFreezeEndTime": int,
    },
)

GetWalletResult = TypedDict(
    "GetWalletResult",
    {
        "uid": str,
        "wid": int,
        "sid": str,
        "pvencstr": str,
        "encryptDevicePassword": str,
    },
)


def get_wallet_info(access_token: str) -> WalletInfo:
    """
    사용자 MPC 지갑을 조회합니다.

    Args:
        access_token (str): 지갑 사용자의 JWT Token

    WalletInfo example:
    >>> {
        "_id": "657bdc790b67b600128a865f",
        "uid": "d5b440b8-469b-4e16-8978-d78b73a09c4e",
        "wid": 6,
        "email": "test_0@myabcwallet.com",
        "accounts": [
            {
            "id": "0",
            "sid": "0xbE616d5b24903efc58149f3c7511FeC2085c176e",
            "ethAddress": "0xbE616d5b24903efc58149f3c7511FeC2085c176e",
            "icon": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4Hs....",
            "name": "Account 1",
            "signer": "mpc",
            "pubkey": "0x025c5d89f60eba1b8fc5c2bd2fa28eefe48f4c950815acd7...."
            }
        ],
        "favorites": [],
        "autoconfirms": [],
        "twoFactorEnabled": false,
        "twoFactorResetRetryCount": 0,
        "twoFactorRetryFreezeEndTime": 0,
        "twoFactorFreezeEndTime": 0
    }
    """

    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.get(
        url=f"{waas_base_url}/wapi/v2/mpc/wallets/info",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    r.raise_for_status()
    return r.json()


def get_wallet(
    email: str, encrypted_device_password: str, channel_id: str, access_token: str
) -> GetWalletResult:
    """
    사용자 고유 MPC 지갑을 생성합니다.

    사용자는 1개의 고유 지갑을 소유하게 되며, 이미 생성된 지갑이 존재하는 경우, 기존 지갑을 복구합니다.

    devicePassword는 생성 혹은 복구되는 지갑의 Key Share의 암호를 의미합니다.

    GetWalletResult example :
    >>> {
        "uid": "d5b440b8-469b-4e16-8978-d78b73a09c4e",
        "wid": 6,
        "sid": "0xbE616d5b24903efc58149f3c7511FeC2085c176e",
        "pvencstr": "0x1234567890abcdef",
        "encryptDevicePassword": "sEbZRmmOrvmMI83XugEzEVwRpwkBBCeXb4jMq1f8Wao="
    }

    Args:
        email (str): 사용자 이메일
        encrypted_device_password (str): Secure Channel로 암호화된 devicePassword
        channel_id (str): 보안 채널 ID. #  (2)
        access_token (str): 지갑 사용자의 JWT Token

    Returns:
        GetWalletResult: 사용자의 MPC 지갑 정보

    Raises:
        HTTPError: 지갑 생성 요청이 실패한 경우
    """

    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.post(
        url=f"{waas_base_url}/wapi/v2/mpc/wallets",
        headers={
            "Secure-Channel": channel_id,
            "Authorization": f"Bearer {access_token}",
        },
        data={"email": email, "devicePassword": encrypted_device_password},
    )
    return r.json()


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
    )  # (3)

    # 로그인
    email_login_result = login.email_login(
        email,
        encrypted_password,
        secure_channel["channel_id"],
        auth,
    )

    # 성공 시 jwt token 생성됨
    print(f"access_token: {email_login_result['access_token']}")

    device_password = "password"  # (4)
    encrypted_device_password = securechannel.encrypt(secure_channel, device_password)

    wallet = get_wallet(
        email,
        encrypted_device_password,
        secure_channel["channel_id"],
        email_login_result["access_token"],
    )
    print(f"wallet uid: {wallet['uid']}")
    print(f"wallet wid: {wallet['wid']}")
    print(f"wallet sid: {wallet['sid']}")

    wallet_info = get_wallet_info(email_login_result["access_token"])
    print(f"wallet_info uid: {wallet_info['uid']}")
    print(f"wallet_info wid: {wallet_info['wid']}")
    print(f"wallet_info sid: {wallet_info['accounts'][0]['sid']}")


if __name__ == "__main__":
    main()


"""
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
2.  :man_raising_hand: Getting Started > Login 참고 ([getting-started/guide/login/](login.md#__tabbed_1_2))
3.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
4.  :man_raising_hand: devicePassword 는 키 조각 암호화를 위해 사용됩니다. Secure Channel 암호화가 필요합니다.
"""
