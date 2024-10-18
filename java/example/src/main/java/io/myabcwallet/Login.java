/* login.java - WAAS 로그인 API 사용 예제 */

package io.myabcwallet;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;

/* bcprov-jdk18on */
import org.bouncycastle.util.encoders.Base64;

import com.google.gson.Gson;

/* nimbus-jose-jwt */
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/* java-jwt */
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class Login {

    public static String WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com";

    class EmailLoginResult {
        public String access_token;
        public String refresh_token;
        public String token_type;
        public int expire_in;
    }

    public <T> T build(Object object, Class<T> classOfT) throws Exception {
        Gson gson = new Gson();
        String json = gson.toJson(object);
        return build(json, classOfT);
    }

    public <T> T build(String message, Class<T> classOfT) throws Exception {
        Gson gson = new Gson();
        return (T) gson.fromJson(message, classOfT);
    }

    public EmailLoginResult emailLogin(String email, String encryptedPassword, String channelId, String auth) throws Exception {
        /*
        이메일과 암호를 사용하여 로그인 요청을 보냅니다.

        Args:
            email (str): 사용자의 이메일 주소.
            encrypted_password (str): 암호화된 사용자 비밀번호. secure channel 로 암호화 되어야 합니다.
            secure_channel_id (str): 보안 채널 ID.
            auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

        Returns:
            EmailLoginResult: 로그인 요청에 대한 서버의 응답.

        Raises:
            HTTPError: 로그인 요청이 실패한 경우.
        */

        URL url = new URL(WAAS_BASE_URL + "/auth/auth-service/v2/login");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        BufferedReader buffer = null;

        try {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("username=" + email);
            stringBuffer.append("&password=" + encryptedPassword);
            stringBuffer.append("&grant_type=password&audience=https://mw.myabcwallet.com");
            byte[] postData = stringBuffer.toString().getBytes(StandardCharsets.UTF_8);
            int postDataLength = postData.length;
            
            connection.setDoOutput(true);
			connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("charset", "utf-8");
            connection.setRequestProperty("Secure-Channel", channelId);
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
                throw new Exception(String.format("login failed: [%d][%s]", responseCode, response));
            }

            return build(response, EmailLoginResult.class);
        }
        catch(Exception e) {
            e.printStackTrace();
            throw e;
        }
        finally {
            if(buffer != null) buffer.close();
        }
    }

    public EmailLoginResult refreshToken(String token, String auth) throws Exception {
        /*
        refresh token 을 사용하여 access token 을 재발급합니다.

        Args:
            refresh_token (str): refresh token.
            auth (str): 인코딩된 인증 정보. 발급받은 Client ID 와 Client Secret 을 base64 로 인코딩한 값입니다.

        Returns:
            EmailLoginResultDict: 재발급된 access token.
        */

        URL url = new URL(WAAS_BASE_URL + "/auth/auth-service/v2/refresh");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        BufferedReader buffer = null;

        try {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("refresh_token=" + token);
            stringBuffer.append("&grant_type=refresh_token");
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
                throw new Exception(String.format("token refresh failed: [%d][%s]", responseCode, response));
            }

            return build(response, EmailLoginResult.class);
        }
        catch(Exception e) {
            e.printStackTrace();
            throw e;
        }
        finally {
            if(buffer != null) buffer.close();
        }
    }

    public boolean verifyToken(String token) throws Exception {
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
        
        DecodedJWT decodedJWT = JWT.decode(token);
        String issuer = decodedJWT.getIssuer();
		String userPoolId = issuer.split("myabcwallet.com/")[1];

        URL url = new URL(WAAS_BASE_URL + "/jwk/key-service/" + userPoolId + "/.well-known/jwks.json");
        JWKSet jwkSet = JWKSet.load(url.openStream());
        JWK jwk = jwkSet.getKeyByKeyId(decodedJWT.getKeyId());

        try {
            ECPublicKey ecPublicKey = jwk.toECKey().toECPublicKey();
            Algorithm algorithm = Algorithm.ECDSA256(ecPublicKey, null);
            algorithm.verify(decodedJWT);
            return true;
        }
        catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        String email = "test01@ahnlab.com"; // 사용자 이메일
        String password = "0123456789";   // 사용자 비밀번호
        String clientId = "Client ID";  // 발급받은 Client ID
        String clientSecret = "Client Secret";  // 발급받은 Client Secret

        Login login = new Login();

        // Secure Channel 생성
        SecureChannel secureChannel = new SecureChannel();
        secureChannel.create("plainText");

        // password 는 Secure Channel 암호화가 필요합니다.
        String encryptedPassword = secureChannel.encrypt(password);

        // Cliend ID / Client Secret
        String inputString = clientId + ":" + clientSecret;
        String auth = new String(Base64.encode(inputString.getBytes()));

        EmailLoginResult emailLoginResult = login.emailLogin(email, encryptedPassword, secureChannel.getChannelId(), auth);

        // 성공 시 jwt 생성됨
        System.out.println("access_token: " + emailLoginResult.access_token);
        System.out.println("refresh_token: " + emailLoginResult.refresh_token);

        // jwt 검증
        boolean verifyResult = login.verifyToken(emailLoginResult.access_token);
        System.out.println("verifyResult: " + verifyResult);

        emailLoginResult = login.refreshToken(emailLoginResult.refresh_token, auth);

        // 성공 시 jwt 재발급됨
        System.out.println("access_token: " + emailLoginResult.access_token);
        System.out.println("refresh_token: " + emailLoginResult.refresh_token);

        // jwt 검증
        verifyResult = login.verifyToken(emailLoginResult.access_token);
        System.out.println("verifyResult: " + verifyResult);
    }

    /*
    1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/login/](secure-channel.md#__tabbed_1_2))
    2.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
    */
}
