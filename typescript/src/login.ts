import axios, { HttpStatusCode } from 'axios';
import jwt, { JwtHeader, JwtPayload } from 'jsonwebtoken';
import qs from 'qs';
import { createSecureChannel, encrypt } from './secureChannel'; // (1)

/*
	해당 예제는 정상동작하는 상황을 가정하고, 에러 처리를 따로하지 않음
	구현시에 에러 및 예외처리 적용 필요
*/
const WAAS_BASE_URL: string = 'https://dev-api.waas.myabcwallet.com';
function getBaseURL(): string {
  const waas_base_url: string = process.env.WAAS_BASE_URL || WAAS_BASE_URL;
  return waas_base_url;
}

type emailLoginResult = {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiredIn: string;
};

async function emailLogin(
  email: string,
  encryptedPassword: string,
  secureChannelID: string,
  auth: string,
): Promise<emailLoginResult> {
  /*
	   이메일과 암호를 사용하여 로그인 요청을 보냅니다.

	   Args:
	       email (str): 사용자의 이메일 주소.
	       encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
	       secure_channel_id (str): 보안 채널 ID.
	       auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

	   Returns:
	       emailLoginResult: 로그인 요청에 대한 서버의 응답.

	   Raises:
	       HTTPError: 로그인 요청이 실패한 경우.
	*/
  try {
    const urlStr = `${getBaseURL()}/auth/auth-service/v2/login`;
    const data = qs.stringify({
      grant_type: 'password',
      username: email,
      password: encryptedPassword,
      audience: 'https://mw.myabcwallet.com',
    });

    const response = await axios.post(urlStr, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Secure-Channel': secureChannelID,
        Authorization: auth,
      },
    });

    const res: emailLoginResult = {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token,
      tokenType: response.data.token_type,
      expiredIn: response.data.expired_in,
    };

    return res;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(
        `fail to email login. stataus code: ${error.response?.status}`,
      );
    }

    throw new Error(`fail to email login`);
  }
}

async function refreshToken(
  refreshToken: string,
  auth: string,
): Promise<emailLoginResult> {
  /*
		refresh token 을 사용하여 access token 을 재발급합니다.

		Args:
		    refresh_token (str): refresh token.
		    auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

		Returns:
		    emailLoginResult: 재발급된 access token.
	*/

  try {
    const urlStr = `${getBaseURL()}/auth/auth-service/v2/login`;
    const data = qs.stringify({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });

    const response = await axios.post(urlStr, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: auth,
      },
    });

    const res: emailLoginResult = {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token,
      tokenType: response.data.token_type,
      expiredIn: response.data.expired_in,
    };

    return res;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(
        `fail to refresh token. stataus code: ${error.response?.status}`,
      );
    }

    throw new Error(`fail to refresh token`);
  }
}

interface JWKKey {
  kid: string;
  [key: string]: any;
}

interface JWKDict {
  keys: JWKKey[];
}

async function verifyToken(token: string): Promise<boolean> {
  /*
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
	*/
  try {
    // JWT 토큰 디코딩 (서명 검증 없이)
    const decodedToken = jwt.decode(token, { complete: true }) as {
      header: JwtHeader;
      payload: JwtPayload;
    };
    if (!decodedToken) {
      throw new Error('Failed to parse token');
    }

    const claims = decodedToken.payload;
    const iss = claims.iss as string;
    const parsedURL = new URL(iss);
    const userPoolID = parsedURL.pathname.substring(1);

    const response = await axios.get(
      `${getBaseURL()}/jwk/key-service/${userPoolID}/.well-known/jwks.json`,
    );
    if (response.status !== 200) {
      throw new Error(`Request failed with status: ${response.status}`);
    }

    const result: JWKDict = response.data;

    // JWT 헤더에서 kid 값 추출
    const jwtHeader = decodedToken.header;
    const kid = jwtHeader.kid;
    if (!kid) {
      throw new Error('Failed to get kid from token header');
    }

    // kid 값이 일치하는 첫 번째 키 찾기
    const foundKey = result.keys.find((key) => key.kid === kid);

    return foundKey !== undefined;
  } catch (error) {
    const errMsg: string = 'fail to verify token';
    if (axios.isAxiosError(error)) {
      throw new Error(`${errMsg} code: ${error.response?.status}`);
    } else if (error instanceof Error) {
      throw new Error(`${errMsg} message: ${error.message}`);
    } else {
      throw new Error(`${errMsg} code: ${error}`);
    }
  }
}

export async function loginScenario() {
  const email: string = 'email@email.com'; // 사용자 이메일
  const password: string = 'password'; // 사용자 비밀번호
  const clientID: string = 'client id'; // 발급받은 Client ID
  const clientSecret: string = 'client secret'; // 발급받은 Client Secret

  // Secure Channel 생성
  const secureChannelRes = await createSecureChannel();

  // password는 Secure Channel 암호화가 필요합니다.
  const encryptedPassword = encrypt(secureChannelRes, password);

  // Client ID / Client Secret
  const auth = Buffer.from(`${clientID}:${clientSecret}`).toString('base64'); // (2)

  // 로그인
  const loginResult = await emailLogin(
    email,
    encryptedPassword,
    secureChannelRes.ChannelID,
    auth,
  );

  // 성공시 jwt token 생성됨
  console.log(`access token : ${loginResult.accessToken}`);
  console.log(`refresh token : ${loginResult.refreshToken}`);

  // jwt token 검증
  let verifyResult = await verifyToken(loginResult.accessToken);
  console.log(`verify result : ${verifyResult}`);

  // refresh token을 이용하여 token 재발급
  const refreshTokenResult = await refreshToken(loginResult.refreshToken, auth);

  // 성공 시 jwt token 재발급됨
  console.log(`access token : ${loginResult.accessToken}`);
  console.log(`refresh token : ${loginResult.refreshToken}`);

  // jwt token 검증
  verifyResult = await verifyToken(refreshTokenResult.accessToken);
  console.log(`verify result : ${verifyResult}`);
}

/*
1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/secure-channel/](secure-channel.md#__tabbed_1_1))
2.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
*/
