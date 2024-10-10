"""securechannel.py - WAAS Secure Channel API 사용 예제"""

import base64
import os
from typing import TypedDict

import requests  # pip install requests
from Crypto.Cipher import AES  # pip install pycryptodome
from Crypto.Util import Padding
from ecdsa import ECDH, NIST256p, SigningKey, VerifyingKey  # pip install ecdsa


WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com"


SecureChannel = TypedDict(
    "SecureChannel",
    {
        "private_key": str,
        "message": str,
        "encrypted": str,
        "server_public_key": str,
        "channel_id": str,
    },
)

KayPair = TypedDict(
    "KayPair",
    {
        "private_key": SigningKey,
        "public_key": VerifyingKey,
    },
)

CreateSecureChannelResponse = TypedDict(
    "CreateSecureChannelResponse",
    {
        "publickey": str,
        "encrypted": str,
        "channelid": str,
    },
)


def create_secure_channel(
    secure_channel_message: str = "ahnlabblockchaincompany",
) -> SecureChannel:
    """
    생성된 공개 키와 보안 채널 메시지를 사용하여 보안 채널을 생성합니다.

    `WAAS_BASE_URL` 환경 변수를 사용하여 WAAS API 서버의 기본 URL을 설정할 수 있습니다.

    Dev : https://dev-api.waas.myabcwallet.com
    Production : https://api.waas.myabcwallet.com

    참고:
    https://docs.waas.myabcwallet.com/ko/getting-started/guide/secure-channel/

    Args:
        secure_channel_message (str): 요청에 사용되는 plain 은 채널 생성 확인을 위한 임시 문자열

    Returns:
        SecureChannel: 보안 채널 데이터.

    Raises:
        HTTPError: 보안 채널 생성 요청이 실패한 경우.
    """

    key_pair = create_keypair()
    public_key_str = key_pair["public_key"].to_string().hex()
    public_key = f"04{public_key_str}"
    secure_channel_message = "ahnlabblockchaincompany"  # (1)

    waas_base_url = os.getenv("WAAS_BASE_URL", WAAS_BASE_URL)
    r = requests.post(
        url=f"{waas_base_url}/secure/channel/create",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"pubkey": public_key, "plain": secure_channel_message},
    )
    r.raise_for_status()
    resp: CreateSecureChannelResponse = r.json()

    return {
        "channel_id": resp["channelid"],
        "private_key": key_pair["private_key"].to_string().hex(),
        "server_public_key": resp["publickey"],
        "message": secure_channel_message,
        "encrypted": resp["encrypted"],
    }


def verify_secure_channel(secure_channel: SecureChannel) -> bool:
    return secure_channel["message"] == decrypt(
        secure_channel, secure_channel["encrypted"]
    )


def encrypt(secure_channel: SecureChannel, message: str) -> str:
    cipher = get_aes_cipher(
        secure_channel["private_key"], secure_channel["server_public_key"]
    )
    padded_msg = Padding.pad(message.encode("utf-8"), AES.block_size, "pkcs7")
    enc_msg = cipher.encrypt(padded_msg)
    return base64.b64encode(enc_msg).decode("utf-8")


def decrypt(secure_channel: SecureChannel, encrypted_message: str) -> str:
    cipher = get_aes_cipher(
        secure_channel["private_key"], secure_channel["server_public_key"]
    )
    decrypt_msg = cipher.decrypt(base64.b64decode(encrypted_message))
    return Padding.unpad(decrypt_msg, AES.block_size, "pkcs7").decode("utf-8")


def create_keypair() -> KayPair:
    ECPrivateKey = SigningKey.generate(curve=NIST256p)
    ECPublicKey = ECPrivateKey.verifying_key
    return {
        "private_key": ECPrivateKey,
        "public_key": ECPublicKey,
    }


def get_aes_cipher(private_key: str, public_key: str):
    # Public key와  Private Key로 ECDH 연산하여 shared secret 생성
    pubkey = VerifyingKey.from_string(bytes.fromhex(public_key), curve=NIST256p)
    privkey = SigningKey.from_string(bytes.fromhex(private_key), curve=NIST256p)
    ecdh = ECDH(curve=NIST256p, private_key=privkey, public_key=pubkey)
    bytes_secret = ecdh.generate_sharedsecret_bytes()
    return AES.new(bytes_secret[0:16], AES.MODE_CBC, bytes_secret[16:32])


def main():
    # Secure Channel 생성
    secure_channel = create_secure_channel()
    print(secure_channel)

    # Secure Channel 검증
    verify_result = verify_secure_channel(secure_channel)
    print(f"Secure Channel verify result: {verify_result}")

    # Secure Channel 을 사용한 메시지 암복호화
    message = "hello, waas"
    encrypted_message = encrypt(secure_channel, message)
    decrypted_message = decrypt(secure_channel, encrypted_message)
    print(f"message encrypt result: {encrypted_message == decrypted_message}")


if __name__ == "__main__":
    main()

"""
1.  :man_raising_hand: 요청에 사용되는 plain은 채널 생성 확인 여부를 위한 임시 문자열을 사용해야합니다.
"""
