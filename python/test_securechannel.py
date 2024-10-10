import securechannel


def test_get_secure_channel_and_verify():
    secure_channel = securechannel.create_secure_channel()
    assert securechannel.verify_secure_channel(secure_channel)


def test_encrypt_message_using_secure_channel():
    secure_channel = securechannel.create_secure_channel()
    message = "hello, waas"
    encrypted_message = securechannel.encrypt(secure_channel, message)
    decrypted_message = securechannel.decrypt(secure_channel, encrypted_message)
    assert message == decrypted_message


def test_create_keypair():
    # 생성
    key_pair1 = securechannel.create_keypair()
    key_pair2 = securechannel.create_keypair()

    # private key, public key 생성됨
    assert key_pair1["private_key"]
    assert key_pair1["public_key"]

    assert key_pair2["private_key"]
    assert key_pair2["public_key"]

    public_key_hex1 = key_pair1["public_key"].to_string().hex()
    assert len(public_key_hex1) == 128

    public_key_hex2 = key_pair2["public_key"].to_string().hex()
    assert len(public_key_hex2) == 128

    # 매번 다른 키 생성
    assert public_key_hex1 != public_key_hex2
