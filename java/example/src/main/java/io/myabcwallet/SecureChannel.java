package io.myabcwallet;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* bcpkix-jdk18on */
/* bcprov-jdk18on */
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.google.gson.Gson;

/* nimbus-jose-jwt */
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.ByteUtils;

public class SecureChannel {

    public static String secp256r1 = "secp256r1";
	public static String secp256k1 = "secp256k1";

    public static String WAAS_BASE_URL = "https://dev-api.waas.myabcwallet.com";

    static {
        try {
            if(Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProviderSingleton.getInstance());
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private String message;
    private String channelId;
    private byte[] sharedSecret;

    private byte[] key;
    private byte[] iv;

    public <T> T build(Object object, Class<T> classOfT) throws Exception {
        Gson gson = new Gson();
        String json = gson.toJson(object);
        return build(json, classOfT);
    }

    public <T> T build(String message, Class<T> classOfT) throws Exception {
        Gson gson = new Gson();
        return (T) gson.fromJson(message, classOfT);
    }

    public String getChannelId() {
        return this.channelId;
    }

    public byte[] getSharedSecret() {
        return this.sharedSecret;
    }

    @Override
    public String toString() {
        return "SecureChannel [message=" + message + ", channelId=" + channelId + ", sharedSecret=" + Hex.toHexString(sharedSecret) + "]";
    }

    private KeyPair createKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        ECGenParameterSpec escp = new ECGenParameterSpec(secp256r1);
		keyPairGenerator.initialize(escp, new SecureRandom());
		return keyPairGenerator.generateKeyPair();
    }

    private PublicKey loadPublicKey(byte[] data) throws Exception {
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec(secp256r1);
		ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
		return kf.generatePublic(pubKey);
	}

    private PrivateKey loadPrivateKey(byte[] data) throws Exception {
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec(secp256r1);
		ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
		return kf.generatePrivate(prvkey);
	}

    private byte[] getSharedSecretWithECDH(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // Public key와  Private Key로 ECDH 연산하여 shared secret 생성
		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
		
		keyAgreement.init(privateKey);
		keyAgreement.doPhase(publicKey, true);
		
		byte[] secret = keyAgreement.generateSecret();
		
		return secret;
	}

    public String create(String plainText) throws Exception {
        /*
        생성된 공개 키와 보안 채널 메시지를 사용하여 보안 채널을 생성합니다.

        `WAAS_BASE_URL` 환경 변수를 사용하여 WAAS API 서버의 기본 URL을 설정할 수 있습니다.

        Dev : https://dev-api.waas.myabcwallet.com
        Production : https://api.waas.myabcwallet.com

        참고:
        https://docs.waas.myabcwallet.com/ko/getting-started/guide/secure-channel/

        Args:
            plainText (str): 요청에 사용되는 plain 은 채널 생성 확인을 위한 임시 문자열

        Returns:
            encrypted (str): 암호화 데이터.

        Raises:
            Exception: 보안 채널 생성 요청이 실패한 경우.
        */
        this.message = plainText; // (1)

        KeyPair keyPair = createKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();

        ECPublicKey ecPublicKey = (ECPublicKey) this.publicKey;
		byte[] bytes = ecPublicKey.getQ().getEncoded(false);

        String data = "pubkey=" + Hex.toHexString(bytes) + "&plain=" + plainText;

        byte[] postData = data.getBytes(StandardCharsets.UTF_8);
		int postDataLength = postData.length;

        BufferedReader bufferedReader = null;

        try {
            URL url = new URL(WAAS_BASE_URL + "/secure/channel/create");
    		HttpURLConnection connection = (HttpURLConnection) url.openConnection();

			connection.setDoOutput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("charset", "utf-8");
			connection.setRequestProperty("Content-Length", Integer.toString(postDataLength));
            connection.setConnectTimeout(10 * 1000);

            DataOutputStream stream = new DataOutputStream(connection.getOutputStream());
			stream.write(postData);
			
			bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
			StringBuilder sb = new StringBuilder();
			String line = null;
			
			while ((line = bufferedReader.readLine()) != null) {
				sb.append(line);
			}
			
			String response = sb.toString();

            int responseCode = connection.getResponseCode();
            if(responseCode != 200) {
                throw new Exception(String.format("create channel failed: [%d][%s]", responseCode, response));
            }

            Map map = build(response, Map.class);
            this.channelId = (String) map.get("channelid");
            String serverPubKey = (String) map.get("publickey");
            String encrypted = (String) map.get("encrypted");

            PublicKey publicKey = loadPublicKey(Hex.decode(serverPubKey));
            this.sharedSecret = getSharedSecretWithECDH(privateKey, publicKey);

            this.key = ByteUtils.subArray(this.sharedSecret, 0, 16);
            this.iv = ByteUtils.subArray(this.sharedSecret, 16, 16);

            return encrypted;
        }
        catch(Exception e) {
            throw e;
        }
        finally {
            if(bufferedReader != null) bufferedReader.close();
        }
    }

    public boolean verify(String encryptedMessage) throws Exception {
        String plainText = decrypt(encryptedMessage);
        if(this.message.equals(plainText)) {
            return true;
        }
        return false;
    }

    public String encrypt(String message) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
		
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
		
		byte[] data = cipher.doFinal(message.getBytes());
        
        return new String(Base64.encode(data));
    }

    public String decrypt(String encryptedMessage) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
		
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);

        byte[] data = Base64.decode(encryptedMessage);
		
		return new String(cipher.doFinal(data));
    }

    public static void main(String[] args) throws Exception {
        // Secure Channel 생성
        SecureChannel secureChannel = new SecureChannel();
        String encrypted = secureChannel.create("ahnlabblockchaincompany");
        System.out.println(secureChannel.toString());

        // Secure Channel 검증
        boolean result = secureChannel.verify(encrypted);
        System.out.println("Secure Channel verify result: " + result);

        // Secure Channel 을 사용한 메시지 암복호화
        String message = "hello, waas";
        String encryptedMessage = secureChannel.encrypt(message);
        String decryptedMessage = secureChannel.decrypt(encryptedMessage);
        System.out.println("message encrypt result: " + message + " == " + new String(decryptedMessage));
    }

    /*
    1.  :man_raising_hand: 요청에 사용되는 plain은 채널 생성 확인 여부를 위한 임시 문자열을 사용해야합니다.
    */
}
