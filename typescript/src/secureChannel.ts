// securechannel.ts - WAAS Secure Channel API 사용 예제
import axios from 'axios';
import crypto from 'crypto';
import CryptoJS from 'crypto-js';
import qs from 'qs';

/*
	해당 예제는 정상동작하는 상황을 가정하고, 에러 처리를 따로하지 않음
	구현시에 에러 및 예외처리 적용 필요
  ts를 js로 빌드하여, dist파일을 실행하도록 package.json설정하여 작성된 예제 
  package.json 에 해당 스크립트 참고
  ``` json
    "scripts": {
      "start": "tsc | node dist/index.js",
    },
  ```
*/

const WAAS_BASE_URL: string = 'https://dev-api.waas.myabcwallet.com';

// 필수 함수 아님. 유틸성 함수
function getBaseURL(): string {
  const waas_base_url: string = process.env.WAAS_BASE_URL || WAAS_BASE_URL;
  return waas_base_url;
}
type secureChannel = {
  PrivateKey: string;
  Message: string;
  Encrypted: string;
  ServerPublicKey: string;
  ChannelID: string;
};

interface keyPair {
  privateKey: crypto.ECDH;
  publicKey: crypto.ECDH;
}

export async function createSecureChannel(): Promise<secureChannel> {
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

function createKeypair(): keyPair {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return {
    privateKey: ecdh,
    publicKey: ecdh,
  };
}

function verifySecureChannel(secureChannel: secureChannel): boolean {
  const decryptedMessage = decrypt(secureChannel, secureChannel.Encrypted);
  return secureChannel.Message === decryptedMessage;
}

export function encrypt(secureChannel: secureChannel, message: string): string {
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

function decrypt(
  secureChannel: secureChannel,
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

export async function secureChannelScenario() {
  // Secure channel 생성
  const secureChannelRes: secureChannel = await createSecureChannel();
  console.log('Secure Channel 생성 완료\n', secureChannelRes);

  // Secure Channel 검증
  const verifyResult: boolean = verifySecureChannel(secureChannelRes);
  console.log(`Secure Channel Verify Result: ${verifyResult}\n`); // true 예상

  // Secure Channel 을 사용한 메시지 암복호화
  const message: string = 'hello, waas';
  const encryptedMessage: string = encrypt(secureChannelRes, message);
  const decryptedMessage: string = decrypt(secureChannelRes, encryptedMessage);

  console.log(`message encrypt result: ${message === decryptedMessage}\n`); // true 예상
}

/*
1.  :man_raising_hand: 요청에 사용되는 plain은 채널 생성 확인 여부를 위한 임시 문자열을 사용해야합니다.
*/
