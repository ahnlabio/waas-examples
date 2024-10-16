import crypto from 'crypto';
import CryptoJS from 'crypto-js';
import axios from 'axios';
import qs from 'qs';

/*
	해당 예제는 정상동작하는 상황을 가정하고, 에러 처리를 따로하지 않음
	구현시에 에러 및 예외처리 적용 필요
*/
const WAAS_BASE_URL: string = 'https://dev-api.waas.myabcwallet.com';
function getBaseURL(): string {
    const waas_base_url: string = process.env.WAAS_BASE_URL || WAAS_BASE_URL;
    return waas_base_url;
}

const AES_BLOCK_SIZE = 16; // AES 블록 크기

type SecureChannel = {
    PrivateKey: string;
    Message: string;
    Encrypted: string;
    ServerPublicKey: string;
    ChannelID: string;
};

interface KeyPair {
    privateKey: crypto.ECDH;
    publicKey: crypto.ECDH;
}

async function CreateSecureChannel(): Promise<SecureChannel> {
    /*
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
    */

    try {
        const keyPair = createKeypair();
        const secureChannelMessage: string = 'ahnlabblockchaincompany'; // (1)

        // HTTP POST 요청 보내기
        const formData = qs.stringify({
            pubkey: keyPair.publicKey.getPublicKey('hex'),
            plain: secureChannelMessage,
        });

        const urlStr = `${getBaseURL()}/secure/channel/create`;
        const response = await axios.post(urlStr, formData, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        if (response.status !== 200) {
            throw new Error(
                `fail to create channel request, status code: ${response.status}`,
            );
        }

        // 바이트 배열을 16진수 문자열로 인코딩
        const privateKeyStr = keyPair.privateKey.getPrivateKey('hex');

        return {
            ChannelID: response.data.channelid,
            Encrypted: response.data.encrypted,
            ServerPublicKey: response.data.publickey,
            Message: secureChannelMessage,
            PrivateKey: privateKeyStr,
        };
    } catch (error) {
        console.error('create secure channel error:', error);
        throw error;
    }
}

function createKeypair(): KeyPair {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return {
        privateKey: ecdh,
        publicKey: ecdh,
    };
}

function VerifySecureChannel(secureChannel: SecureChannel): boolean {
    const decryptedMessage = Decrypt(secureChannel, secureChannel.Encrypted);
    return secureChannel.Message === decryptedMessage;
}

function Encrypt(secureChannel: SecureChannel, message: string): string {
    const { block, iv } = getAESCipher(
        secureChannel.PrivateKey,
        secureChannel.ServerPublicKey,
    );

    const messageWordArray: CryptoJS.lib.WordArray =
        CryptoJS.enc.Utf8.parse(message);

    const encMsg = CryptoJS.AES.encrypt(
        messageWordArray,
        CryptoJS.enc.Hex.parse(block.toString('hex')),
        {
            iv: CryptoJS.enc.Hex.parse(iv.toString('hex')),
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7, // Pkcs7 패딩 사용
        },
    );

    return encMsg.toString();
}

function Decrypt(
    secureChannel: SecureChannel,
    encryptedMessage: string,
): string {
    const { block, iv } = getAESCipher(
        secureChannel.PrivateKey,
        secureChannel.ServerPublicKey,
    );
    const decypteKey: CryptoJS.lib.WordArray = CryptoJS.enc.Hex.parse(
        block.toString('hex'),
    );

    const copt: object = {
        iv: CryptoJS.enc.Hex.parse(iv.toString('hex')),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    };
    const encMsg = CryptoJS.AES.decrypt(encryptedMessage, decypteKey, copt);

    const decryptedMsg = encMsg.toString(CryptoJS.enc.Utf8);
    return decryptedMsg;
}

function getAESCipher(
    privateKeyStr: string,
    publicKeyStr: string,
): { block: Buffer; iv: Buffer } {
    const privateKeyBytes = Buffer.from(privateKeyStr, 'hex');
    const publicKeyBytes = Buffer.from(publicKeyStr, 'hex');

    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(privateKeyBytes);
    const sharedSecret = ecdh.computeSecret(publicKeyBytes);

    const key = sharedSecret.slice(0, 16);
    const iv = sharedSecret.slice(16, 32);

    return { block: key, iv: iv };
}

export async function SecureChannelScenario() {
    // Secure channel 생성
    const secureChannel: SecureChannel = await CreateSecureChannel();
    console.log('Secure Channel 생성 완료\n', secureChannel);

    // Secure Channel 검증
    const verifyResult: boolean = VerifySecureChannel(secureChannel);
    console.log(`Secure Channel Verify Result: ${verifyResult}\n`); // true 예상

    // Secure Channel 을 사용한 메시지 암복호화
    const message: string = 'hello, waas';
    const encryptedMessage: string = Encrypt(secureChannel, message);
    const decryptedMessage: string = Decrypt(secureChannel, encryptedMessage);

    console.log(`message encrypt result: ${message === decryptedMessage}\n`); // true 예상
}

/*
1.  :man_raising_hand: 요청에 사용되는 plain은 채널 생성 확인 여부를 위한 임시 문자열을 사용해야합니다.
*/
