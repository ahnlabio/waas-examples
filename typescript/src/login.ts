import axios, { HttpStatusCode } from "axios";
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

type emailLoginResult = {
    accessToken:string
    refreshToken:string
    tokenType:string
    expiredIn:string
}

async function emailLogin(email:string, encryptedPassword:string, secureChannelID:string, auth:string): Promise<emailLoginResult> {
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
        const urlStr = `${getBaseURL()}/auth/auth-service/v2/login`
        const data = qs.stringify({
            grant_type : "password",
            username : email,
            password : encryptedPassword,
            audience : "https://mw.myabcwallet.com"
        })
    
        const response = await axios.post(urlStr, data, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Secure-Channel': secureChannelID,
                'Authorization': auth,
            }
        })
    
        if (response.status !== HttpStatusCode.Ok) {
            throw new Error(`fail to email login ${response.status}`)
        }

        const res:emailLoginResult = {
            accessToken : response.data.
        }

        return 
    } catch(e) {
        console.error(`fail to email login`)
    }
}