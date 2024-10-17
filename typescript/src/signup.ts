import axios, { formToJSON, HttpStatusCode } from 'axios';
import qs from 'qs';
import { createSecureChannel, encrypt } from './secureChannel';

/*
	해당 예제는 정상동작하는 상황을 가정하고, 에러 처리를 따로하지 않음
	구현시에 에러 및 예외처리 적용 필요
*/
const WAAS_BASE_URL: string = 'https://dev-api.waas.myabcwallet.com';
function getBaseURL(): string {
  const waas_base_url: string = process.env.WAAS_BASE_URL || WAAS_BASE_URL;
  return waas_base_url;
}

async function isExistUser(email: string): Promise<boolean> {
  /*
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
	*/
  try {
    const urlStr = `${getBaseURL()}/member/user-management/users/${email}?serviceid=https://mw.myabcwallet.com`;
    const response = await axios.get(urlStr);
    return response.status !== 200;
  } catch (e) {
    throw new Error(`fail to is exist user check`);
  }
}

async function registerEmailUser(
  email: string,
  encryptedPassword: string,
  verificationCode: string,
  channelID: string,
  auth: string,
  overage: number,
  agree: number,
  collect: number,
  thirdParty: number,
  advertise: number,
) {
  /*
	   회원 가입

	   성공시 오류 없이 종료

	   Args:
	       email (str): 사용자 이메일
	       encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
	       verification_code (str): 인증 코드. 이메일로 전송된 인증 코드를 입력합니다.
	       channel_id (str): 보안 채널 ID.
	       auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.
	       overage (int): 14세 이상 사용자 동의
	       agree (int): 서비스 이용 약관 동의
	       collect (int): 개인정보 수집 및 이용 동의
	       third_party (int): 제3자 정보 제공 동의
	       advertise (int): 광고성 정보 수신 동의
	*/
  try {
    const urlStr: string = `${getBaseURL()}/member/user-management/users/v2/adduser`;
    const formData = qs.stringify({
      username: email,
      password: encryptedPassword,
      code: verificationCode,
      overage: overage,
      agree: agree,
      collect: collect,
      third_party: thirdParty,
      advertise: advertise,
      serviceid: 'https://mw.myabcwallet.com',
    });
    const response = await axios.post(urlStr, formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${auth}`,
        'Secure-Channel': `${channelID}`,
      },
    });

    if (response.status !== HttpStatusCode.Ok) {
      throw new Error(
        `fail to register email user, status code: ${response.status}`,
      );
    }
  } catch (e) {
    console.error(`fail to register email user`);
  }
}

type verifyCodeType = 'verify' | 'changepassword' | 'initpassword';

const authCode: verifyCodeType = 'verify';
const changePasswordCode: verifyCodeType = 'changepassword';
const initPasswordCode: verifyCodeType = 'initpassword';

async function sendVerificationCode(email: string, lang: string) {
  /*
	   사용자 이메일로 인증 코드를 전송합니다.

	   성공하면 함수는 오류 없이 종료

	   Args:
	       email (str): 인증 코드를 전송할 사용자의 이메일 주소.
	       lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

	   Raises:
	       HTTPError: 요청이 실패한 경우.

	*/
  await sendCode(email, lang, authCode);
}

async function SendChangePasswordCode(email: string, lang: string) {
  /*
	   사용자 이메일로 패스워드 변경 인증 코드를 전송합니다.

	   성공하면 함수는 오류 없이 종료

	   Args:
	       email (str): 인증 코드를 전송할 사용자의 이메일 주소.
	       lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

	   Raises:
	       HTTPError: 요청이 실패한 경우.
	*/
  await sendCode(email, lang, changePasswordCode);
}

async function SendResetPasswordCode(email: string, lang: string) {
  /*
	   사용자 이메일로 패스워드 초기화 인증 코드를 전송합니다.

	   성공하면 함수는 오류 없이 종료

	   Args:
	       email (str): 인증 코드를 전송할 사용자의 이메일 주소.
	       lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".

	   Raises:
	       HTTPError: 요청이 실패한 경우.
	*/
  await sendCode(email, lang, initPasswordCode);
}

async function sendCode(email: string, lang: string, template: verifyCodeType) {
  try {
    const baseURL = getBaseURL();
    const url = new URL(`${baseURL}/member/mail-service/${email}/sendcode`);

    url.searchParams.append('lang', lang);
    url.searchParams.append('template', template);

    const response = await axios.get(url.toString());

    if (response.status !== 200) {
      throw new Error(`Request failed with status code ${response.status}`);
    }
  } catch (error) {
    console.error(`fail to send code`);
  }
}

async function verifyCode(email: string, code: string): Promise<boolean> {
  /*
	   사용자가 입력한 코드가 올바른지 확인합니다.

	   send_verification_code, send_auth_code, send_password_reset_code 함수로 전송된 코드를 확인합니다.

	   Args:
	       email (str): 사용자 이메일 주소.
	       code (str): 사용자가 입력한 코드.

	   Returns:
	       bool: 사용자가 입력한 코드가 올바른 경우 True, 그렇지 않은 경우 False.

	   Raises:
	       HTTPError: 요청이 실패한 경우.
	*/

  try {
    const urlStr = `${getBaseURL()}/member/mail-service/${email}/verifycode`;
    const formData = qs.stringify({
      code: code,
      serviceid: 'https://mw.myabcwallet.com',
    });

    const response = await axios.post(urlStr, formData);
    return response.status === HttpStatusCode.Ok;
  } catch (e) {
    throw new Error(`fail to verify code`);
  }
}

export async function signupScenario() {
  const email: string = 'email@email.com'; // 사용자 이메일
  const password: string = 'password'; // 사용자 비밀번호
  const clientID: string = 'client id'; // 발급받은 Client ID
  const clientSecret: string = 'client secret'; // 발급받은 Client Secret
  const verificationCode: string = 'verification code'; // 사용자가 입력한 인증 코드

  // 이미 가입된 사용자인지 확인합니다.
  const isExist: boolean = await isExistUser(email);
  if (isExist === true) {
    console.error(`${email} is already exist user \n`);
    return;
  }

  console.log(`${email} is not exist\n`);

  // 이메일로 인증 코드를 전송합니다.
  sendVerificationCode(email, 'en');
  console.log('verification code sent');

  // 사용자가 입력한 인증 코드가 올바른지 확인합니다.
  // 인증코드를 발송한 다음 사용자로부터 verification_code를 얻습니다.
  const isValidCode = await verifyCode(email, verificationCode);
  if (!isValidCode) {
    console.error('invalid code', email, verificationCode);
    return;
  }

  // 사용자의 비밀번호를 암호화합니다.
  const secureChannelRes = await createSecureChannel();
  const encryptedPassword = encrypt(secureChannelRes, password);

  // 사용자의 동의를 받습니다.
  const overage = 1;
  const agree = 1;
  const collect = 1;
  const thirdParty = 1;
  const adverise = 1;

  // Client ID / Client Secret
  const auth = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');

  // 사용자를 등록합니다.
  await registerEmailUser(
    email,
    encryptedPassword,
    verificationCode,
    secureChannelRes.ChannelID,
    auth,
    overage,
    agree,
    collect,
    thirdParty,
    adverise,
  );
  console.log('success signup');

  const existResult = await isExistUser(email);
  console.log(`${email} is exist: ${existResult}\n`);
}
