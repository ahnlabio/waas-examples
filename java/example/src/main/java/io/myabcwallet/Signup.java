package io.myabcwallet;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/* bcprov-jdk18on */
import org.bouncycastle.util.encoders.Base64;

public class Signup {

    public static String WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com";

    public static String SERVICE_ID = "https//mw.myabcwallet.com";

    public boolean isExistUser(String email) throws Exception {
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
        URL url = new URL(WAAS_BASE_URL + "/member/user-management/users/" + email + "?serviceid=" + SERVICE_ID);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("charset", "utf-8");

        int code = connection.getResponseCode();

        if(code != 200) return true;
        return false;
    }

    public int registerEmailUser(String email, String encPassword, String verificationCode, String channelId, String auth,
                int overage, int agree, int collect, int thridParty, int adverties) throws Exception {
        /*
        회원 가입
        성공시 오류 없이 종료
        
        Args:
            email (str): 사용자 이메일
            encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
            verification_code (str): 인증 코드. 이메일로 전송된 인증 코드를 입력합니다.
            channel_id (str): 보안 채널 ID.  # (2)
            auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.
            overage (int): 14세 이상 사용자 동의
            agree (int): 서비스 이용 약관 동의
            collect (int): 개인정보 수집 및 이용 동의
            third_party (int): 제3자 정보 제공 동의
            advertise (int): 광고성 정보 수신 동의
        */
        URL url = new URL(WAAS_BASE_URL + "/member/user-management/users/v2/adduser");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        BufferedReader buffer = null;

        try {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("username=" + email);
            stringBuffer.append("&password=" + encPassword);
            stringBuffer.append("&serviceid=" + SERVICE_ID);
            stringBuffer.append("&code=" + verificationCode);
            stringBuffer.append("&overage=" + overage);
            stringBuffer.append("&agree=" + agree);
            stringBuffer.append("&collect=" + collect);
            stringBuffer.append("&thridParty=" + thridParty);
            stringBuffer.append("&adverties=" + adverties);
            byte[] postData = stringBuffer.toString().getBytes(StandardCharsets.UTF_8);
            int postDataLength = postData.length;
            
            connection.setDoOutput(true);
			connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("charset", "utf-8");
            connection.setRequestProperty("Authorization", "Basic " + auth);
			connection.setRequestProperty("Content-Length", Integer.toString(postDataLength));

            DataOutputStream stream = new DataOutputStream(connection.getOutputStream());
			stream.write(postData);
			
			buffer = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
			StringBuilder stringBuilder = new StringBuilder();
            String line = null;
			
			while ((line = buffer.readLine()) != null) {
				stringBuilder.append(line);
			}
			
			String response = stringBuilder.toString();

            int responseCode = connection.getResponseCode();
            if(responseCode != 200) {
                throw new Exception(String.format("register user failed: [%d][%s]", responseCode, response));
            }

            return connection.getResponseCode();
        }
        catch(Exception e) {
            e.printStackTrace();
            throw e;
        }
        finally {
            if(buffer != null) buffer.close();
        }
    }

    public int sendVerificationCode(String email, String lang) throws Exception {
        /*
        사용자 이메일로 인증 코드를 전송합니다.
        
        성공하면 함수는 오류 없이 종료
        
        Args:
            email (str): 인증 코드를 전송할 사용자의 이메일 주소.
            lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".
        
        Raises:
            HTTPError: 요청이 실패한 경우.
        */
        return sendCode(email, lang, "verify");
    }

    public int sendAuthCode(String email, String lang) throws Exception {
        /*
        사용자 이메일로 패스워드 변경 인증 코드를 전송합니다.
        성공하면 함수는 오류 없이 종료
        
        Args:
            email (str): 인증 코드를 전송할 사용자의 이메일 주소.
            lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".
        
        Raises:
            HTTPError: 요청이 실패한 경우.
        */
        return sendCode(email, lang, "changepassword");
    }

    public int sendPasswordResetCode(String email, String lang) throws Exception {
        /*
        사용자 이메일로 패스워드 초기화 인증 코드를 전송합니다.
        
        성공하면 함수는 오류 없이 종료
        
        Args:
            email (str): 인증 코드를 전송할 사용자의 이메일 주소.
            lang (Literal["ko", "en", "ja"], optional): 인증 코드의 언어 설정. Defaults to "en".
        
        Raises:
            HTTPError: 요청이 실패한 경우.
        */
        return sendCode(email, lang, "initpassword");
    }

    public boolean verifyCode(String email, String code) throws Exception {
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
        URL url = new URL(WAAS_BASE_URL + "/member/mail-service/" + email + "/verifycode");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        BufferedReader buffer = null;

        try {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("code=" + code);
            stringBuffer.append("&serviceid=" + SERVICE_ID);
            
            byte[] postData = stringBuffer.toString().getBytes(StandardCharsets.UTF_8);
            int postDataLength = postData.length;
            
            connection.setDoOutput(true);
			connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("charset", "utf-8");
			connection.setRequestProperty("Content-Length", Integer.toString(postDataLength));

            DataOutputStream stream = new DataOutputStream(connection.getOutputStream());
			stream.write(postData);
			
			buffer = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
			StringBuilder stringBuilder = new StringBuilder();
            String line = null;
			
			while ((line = buffer.readLine()) != null) {
				stringBuilder.append(line);
			}
			
			String response = stringBuilder.toString();

            int responseCode = connection.getResponseCode();

            if(responseCode == 200) {
                return true;
            }

            System.out.println(String.format("verify code failed: [%d][%s]", responseCode, response));

            return false;
        }
        catch(Exception e) {
            e.printStackTrace();
            throw e;
        }
        finally {
            if(buffer != null) buffer.close();
        }
    }

    private int sendCode(String email, String lang, String template) throws Exception {
        String params = new String("lang=" + lang + "&tempalte=" + template);
        URL url = new URL(WAAS_BASE_URL + "/member/mail-service/" + email + "/sendcode?" + params);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("charset", "utf-8");

        return connection.getResponseCode();
    }

    public static void main(String[] args) throws Exception {
        String email = "test01@ahnlab.com"; // 사용자 이메일
        String password = "0123456789"; // 사용자 비밀번호
        String language = "en"; // 사용자 언어
        String clientId = "Client ID"; // 발급받은 Client ID
        String ClientSecret = "Client Secret"; // 발급받은 Client Secret
        String verificationCode = "123456"; // 사용자가 입력한 인증 코드

        Signup signup = new Signup();

        // 이미 가입된 사용자인지 확인합니다.
        if(signup.isExistUser(email)) {
            System.err.println(email + " is already exist");
            return;
        }

        System.out.println(email + " is not exist");
        
        // 이메일로 인증 코드를 전송합니다.
        signup.sendVerificationCode(email, language);
        System.out.println("verification code sent");

        // 사용자가 입력한 인증 코드가 올바른지 확인합니다.
        // 인증코드를 발송한 다음 사용자로부터 verification code 를 입력받습니다.
        if(!signup.verifyCode(email, verificationCode)) {
            System.err.println("Invaild Code");
            return;
        }

        // 사용자의 비밀번호를 암호화합니다.
        SecureChannel securechannel = new SecureChannel();
        securechannel.create("plainText");
        String encryptedPassword = securechannel.encrypt(password);

        // 사용자의 동의를 받습니다.
        int overage = 1;
        int agree = 1;
        int collect = 1;
        int third_party = 1;
        int advertise = 1;

        // Client ID / Client Secret
        String auth = new String(Base64.encode((clientId + ":" + ClientSecret).getBytes())); // (3)

        // 사용자를 등록합니다.
        signup.registerEmailUser(
            email,
            encryptedPassword,
            verificationCode,
            securechannel.getChannelId(),
            auth,
            overage,
            agree,
            collect,
            third_party,
            advertise
        );
        System.out.println("signup success");

        System.out.println(email + " is exist: " + signup.isExistUser(email));
    }

    /*
    1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_4))
    2.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
    */
}
