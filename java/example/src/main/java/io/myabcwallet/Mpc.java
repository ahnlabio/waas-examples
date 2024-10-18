package io.myabcwallet;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

/* bcprov-jdk18on */
import org.bouncycastle.util.encoders.Base64;

import com.google.gson.Gson;

import io.myabcwallet.Login.EmailLoginResult;

public class Mpc {

    public static String WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com";

    class WalletAccount {
        String id;
        String sid;
        String ethAddress;
        String icon;
        String name;
        String signer;
        String pubkey;
    }

    class WalletInfo {
        String _id;
        String uid;
        int wid;
        String email;
        List<WalletAccount> accounts;
        List<String> favorites;
        List<String> autoconfirms;
        boolean twoFactorEnabled;
        int twoFactorResetRetryCount;
        int twoFactorRetryFreezeEndTime;
        int twoFactorFreezeEndTime;
    }

    class GetWalletResult {
        String uid;
        int wid;
        String sid;
        String pvencstr;
        String encryptDevicePassword;
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

    public GetWalletResult getWallet(String email, String encDevicePassword, String channelId, String accessToken) throws Exception {
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
            encDevicePassword (str): Secure Channel로 암호화된 devicePassword
            channelId (str): 보안 채널 ID. #  (2)
            accessToken (str): 지갑 사용자의 JWT Token

        Returns:
            GetWalletResult: 사용자의 MPC 지갑 정보

        Raises:
            HTTPError: 지갑 생성 요청이 실패한 경우
        */
        URL url = new URL(WAAS_BASE_URL + "/wapi/v2/mpc/wallets");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        BufferedReader buffer = null;

        try {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("email=" + email);
            stringBuffer.append("&devicePassword=" + encDevicePassword);
            
            byte[] postData = stringBuffer.toString().getBytes(StandardCharsets.UTF_8);
            int postDataLength = postData.length;
            
            connection.setDoOutput(true);
			connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("charset", "utf-8");
            connection.setRequestProperty("Secure-Channel", channelId);
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
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
                throw new Exception(String.format("get wallet failed: [%d][%s]", responseCode, response));
            }

            return build(response, GetWalletResult.class);
        }
        catch(Exception e) {
            e.printStackTrace();
            throw e;
        }
        finally {
            if(buffer != null) buffer.close();
        }
    }

    public WalletInfo getWalletInfo(String acessToken) throws Exception {
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
        
        URL url = new URL(WAAS_BASE_URL + "/wapi/v2/mpc/wallets/info");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        BufferedReader buffer = null;

        try {
            connection.setDoOutput(true);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("charset", "utf-8");
            connection.setRequestProperty("Authorization", "Bearer " + acessToken);

            buffer = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
            StringBuffer stringBuffer = new StringBuffer();
            String line = null;
            
            while ((line = buffer.readLine()) != null) {
                stringBuffer.append(line);
            }
            
            String response = stringBuffer.toString();

            int responseCode = connection.getResponseCode();
            if(responseCode != 200) {
                throw new Exception(String.format("get wallet info failed: [%d][%s]", responseCode, response));
            }

            return build(response, WalletInfo.class);
        }
        catch(Exception e) {
            e.printStackTrace();
            throw e;
        }
        finally {
            if(buffer != null) buffer.close();
        }
    }
    public static void main(String[] args) throws Exception {
        String email = "test01@ahnlab.com";  // 사용자 이메일
        String password = "0123456789";  // 사용자 비밀번호
        String clientId = "Client ID";  // 발급받은 Client ID
        String clientSecret = "Client Secret";  // 발급받은 Client Secret

        // Secure Channel 생성
        SecureChannel secureChannel = new SecureChannel();
        secureChannel.create("plainText");

        // password 는 Secure Channel 암호화가 필요합니다
        String encryptedPassword = secureChannel.encrypt(password);

        // Client ID / Client Secret
        String auth = new String(Base64.encode((clientId + ":" + clientSecret).getBytes())); // (3)

        // 로그인
        Login login = new Login();
        EmailLoginResult emailLoginResult = login.emailLogin(
            email, 
            encryptedPassword, 
            secureChannel.getChannelId(), 
            auth
        );

        // 성공 시 jwt token 생성됨
        System.out.println("access_token: " + emailLoginResult.access_token);

        String devicePassword = "password"; // (4)
        String encDevicePassword = secureChannel.encrypt(devicePassword);

        Mpc mpc = new Mpc();
        
        GetWalletResult getWalletResult = mpc.getWallet(
            email, 
            encDevicePassword, 
            secureChannel.getChannelId(), 
            emailLoginResult.access_token
        );

        System.out.println("wallet uid: " + getWalletResult.uid);
        System.out.println("wallet wid: " + getWalletResult.wid);
        System.out.println("wallet sid: " + getWalletResult.sid);

        WalletInfo walletInfo = mpc.getWalletInfo(emailLoginResult.access_token);

        System.out.println("wallet_info uid: " + walletInfo.uid);
        System.out.println("wallet_info wid: " + walletInfo.wid);
        System.out.println("wallet_info sid: " + walletInfo.accounts.get(0).sid);
    }

    /*
    1.  :man_raising_hand: Getting Started > Secure Channel 참고 ([getting-started/guide/secure-channel/](secure-channel.md#__tabbed_1_2))
    2.  :man_raising_hand: Getting Started > Login 참고 ([getting-started/guide/login/](login.md#__tabbed_1_2))
    3.  :man_raising_hand: 사전에 발급받은 Client ID / Client Secret 이 필요합니다. Client ID 와 Client Secret 을 base64 로 인코딩 해야 합니다.
    4.  :man_raising_hand: devicePassword 는 키 조각 암호화를 위해 사용됩니다. Secure Channel 암호화가 필요합니다.
    */
}
