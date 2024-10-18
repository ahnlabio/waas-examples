// mpc.ts = WAAS 지갑 생성/복구 API 사용 예제

import axios from 'axios';
import qs from 'qs';
import { emailLogin } from './login'; // (2)
import { createSecureChannel, encrypt } from './secureChannel'; // (3)

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

type getWalletResult = {
  uid: string;
  wid: number;
  sid: string;
  pvencstr: string;
  encryptDevicePassword: string;
};

async function getWallet(
  email: string,
  encryptedDevicePassword: string,
  channelID: string,
  accesssToken: string,
): Promise<getWalletResult> {
  /*
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
      channel_id (str): 보안 채널 ID.
      access_token (str): 지갑 사용자의 JWT Token

    Returns:
      GetWalletResult: 사용자의 MPC 지갑 정보

    Raises:
      HTTPError: 지갑 생성 요청이 실패한 경우
	*/
  try {
    const urlStr = `${getBaseURL()}/wapi/v2/mpc/wallets`;
    const data = qs.stringify({
      email: email,
      devicePassword: encryptedDevicePassword,
    });

    const response = await axios.post(urlStr, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Bearer ${accesssToken}`,
        'Secure-Channel': channelID,
      },
    });

    const wallet: getWalletResult = response.data;
    return wallet;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(
        `fail to getWallet. stataus code: ${
          error.status
        }, data: ${JSON.stringify(error.response?.data)}`,
      );
    }

    throw new Error(`fail to getWallet`);
  }
}

type walletAccount = {
  id: string;
  sid: string;
  ethAddress: string;
  icon: string;
  name: string;
  signer: string;
  pubkey: string;
};

type walletInfo = {
  _id: string;
  uid: string;
  wid: number;
  email: string;
  accounts: walletAccount[];
  favorites: string[];
  autoconfirms: string[];
  twoFactorEnabled: boolean;
  twoFactorResetRetryCount: number;
  twoFactorRetryFreezeEndTime: number;
  twoFactorFreezeEndTime: number;
};

async function getWalletInfo(accessToken: string): Promise<walletInfo> {
  /*
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
  */

  try {
    const urlStr = `${getBaseURL()}/wapi/v2/mpc/wallets/info`;
    const response = await axios.get(urlStr, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const walletInfoRes: walletInfo = response.data;

    return walletInfoRes;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(
        `fail to get walletinfo. status code: ${
          error.response?.status
        }, data: ${JSON.stringify(error.response?.data)}`,
      );
    }
    throw new Error(`fail to get walletinfo.`);
  }
}

export async function mpcScenario() {
  const email: string = 'email@email.com'; // 사용자 이메일
  const password: string = 'password'; // 사용자 비밀번호
  const clientID: string = 'client id'; // 발급받은 Client ID
  const clientSecret: string = 'client secret'; // 발급받은 Client Secret

  // Secure Channel 생성
  const secureChannelRes = await createSecureChannel();

  // password는 Secure Channel 암호화가 필요합니다.
  const encryptedPassword = encrypt(secureChannelRes, password);

  // Client ID / Client Secret
  const auth = Buffer.from(`${clientID}:${clientSecret}`).toString('base64'); // (3)

  // 로그인
  const loginResult = await emailLogin(
    email,
    encryptedPassword,
    secureChannelRes.ChannelID,
    auth,
  );

  // 성공시 jwt token 생성됨
  console.log(`access token : ${loginResult.accessToken}`);

  const devicePassword = 'password'; // (4)
  const encryptedDevicePassword = encrypt(secureChannelRes, devicePassword);

  const wallet = await getWallet(
    email,
    encryptedDevicePassword,
    secureChannelRes.ChannelID,
    loginResult.accessToken,
  );
  console.log(`wallet uid: ${wallet.uid}`);
  console.log(`wallet wid: ${wallet.wid}`);
  console.log(`wallet sid: ${wallet.sid}`);

  const walletInfo = await getWalletInfo(loginResult.accessToken);
  console.log(`wallet uid: ${walletInfo.uid}`);
  console.log(`wallet wid: ${walletInfo.wid}`);
  console.log(`wallet sid: ${walletInfo.accounts[0].sid}`);
}

/*
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/secure-channel/](secure-channel.md#__tabbed_1_1))
2.  :man_raising_hand: Getting Started > Login 참고 ([getting-started/guide/login/](login.md#__tabbed_1_1))
3.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
4.  :man_raising_hand: devicePassword 는 키 조각 암호화를 위해 사용됩니다. Secure Channel 암호화가 필요합니다.
*/
