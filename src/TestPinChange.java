import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

public class TestPinChange {
    /*
    Parameters - edit only the following
     */
    final String PAYMENT_INSTRUMENT_ID = "<YOUR_PAYMENT_INSTRUMENT_ID>";
    final String BALANCE_API_KEY = "<YOUR_API_KEY_HERE>";
    final String NEW_PIN = "3456";
    /*
    End Parameters
     */
    @Test
    public void testPinChangeFullyAutomated(){

        final String AES_CIPHER_SPEC = "AES/CBC/NoPadding";
        final String RSA_CIPHER_SPEC = "RSA/NONE/PKCS1Padding";
        final String PUBLIC_KEY_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/publicKey?purpose=pinChange";
        final String PINS_CHANGE_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/pins/change";
        try {
            Security.addProvider(new BouncyCastleProvider());

            //Step 1: Get public key
            String base64EncodedPublicKeyRaw = getRequest(BALANCE_API_KEY, PUBLIC_KEY_ENDPOINT);

            JSONObject jsonObject = new JSONObject(base64EncodedPublicKeyRaw);
            String base64EncodedPublicKey = jsonObject.getString("publicKey");

            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(base64EncodedPublicKey.getBytes(StandardCharsets.UTF_8)));
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

//Step 2.1: Generate AES Key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();

//Step 2.2: Encrypt Key
            Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_SPEC);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            String encryptedKey = Hex.toHexString(rsaCipher.doFinal(aesKey.getEncoded()));

        //Step 3: create an encryption token
            String token = generateRandom16DigitNumber();

            //Step 4: generate an encrypted PIN block
            String formattedToken = "4" + token + "000000000000000";
            byte[] formattedTokenBytes = hexStringToByteArray(formattedToken);

            String random16Hex = generateRandom16Hex();

            String newPinBlock = "44" + NEW_PIN + "AAAAAAAAAA" + random16Hex;
            byte[] newPinBlockBytes = hexStringToByteArray(newPinBlock);

            //encrypt pin
            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_SPEC);
            aesCipher.init(Cipher.ENCRYPT_MODE,aesKey, new IvParameterSpec(new byte[16]));
            byte[] encryptedPinBlock = aesCipher.doFinal(newPinBlockBytes);

            //combine it with the formatted token
            byte[] xorResult = xorByteArrays(encryptedPinBlock, formattedTokenBytes);

            byte[] encryptedPayload = aesCipher.doFinal(xorResult);
            String encryptedPayloadHex = Hex.toHexString(encryptedPayload);

            //Request the PIN change
            StringBuilder resultDataRaw = new StringBuilder();

            URL url = new URL(PINS_CHANGE_ENDPOINT);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("x-api-key", BALANCE_API_KEY);
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Accept", "application/json");
            con.setDoOutput(true);

            String body = "{" +
                    "    \"paymentInstrumentId\":\"" + PAYMENT_INSTRUMENT_ID + "\"," +
                    "    \"encryptedKey\":\"" + encryptedKey + "\",\n" +
                    "    \"token\":\"" + token + "\"," +
                    "    \"encryptedPinBlock\":\"" + encryptedPayloadHex + "\"" +
                    "}";
            System.out.println(body);
            try(OutputStream os = con.getOutputStream()) {
                byte[] input = body.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(con.getInputStream()))) {
                for (String line; (line = reader.readLine()) != null; ) {
                    resultDataRaw.append(line);
                }
            }
            JSONObject response = new JSONObject(resultDataRaw.toString());

            String status = response.getString("status");

            Assertions.assertTrue(status.matches("completed"), "Status is not completed");

        } catch (NoSuchAlgorithmException e) {
            // HmacSHA256 should be supported
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            // The key is invalid
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException |
                 IOException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private String getRequest(String BALANCE_API_KEY, String endpoint) throws IOException {
        StringBuilder comparisonDataRaw = new StringBuilder();

        URL url = new URL(endpoint);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("x-api-key", BALANCE_API_KEY);
        con.setRequestProperty("Content-Type", "application/json");

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(con.getInputStream()))) {
            for (String line; (line = reader.readLine()) != null; ) {
                comparisonDataRaw.append(line);
            }
        }
        return comparisonDataRaw.toString();
    }

    @Test
    public void testKeyGenerationWorkingSampleManual(){
        final String AES_CIPHER_SPEC = "AES/CBC/NoPadding";
        final String RSA_CIPHER_SPEC = "RSA/ECB/PKCS1Padding";
        final String TOKEN = "8374188662676926";
        final String RANDOM_HEX_STRING = "2104CFB1E5B1E9F6";
        final String PUBLIC_KEY_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/publicKey?purpose=pinChange";
        final String PINS_CHANGE_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/pins/change";


        try {
            Security.addProvider(new BouncyCastleProvider());

//Step 1: Get public key
            String base64EncodedPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3LdIuBpzb3J+ZMvdFD5K6biH9Q5LeCx+nOa44rigBTN0eqpxeHlUZ6f6JE3uzoR+C4c8H9SY7kfq2pQjrnI1YtZp3JCeqz+o0B0DMcnXH99Qvr04rmxRQrloFmjRtSgAZqwEpLTJqpNRI9igvPAB+2FxFDQ1vpXvOe7l7017Pic2vSkgC7Xeukahl956sMEwDzj/qBlULEt0SUm1ZH7jCypTvf2H1pmiVEd2I8f5u808F3mJxqDWnGiWBOkqcV4D9XyES/zCwMtmu9MFWeW3dyljTKEhPAxGhwT1Jxe0+pj2Ju9DzcomEqrt9ELRF5yDJboub4h6Kh1BzMtZKMTuVQIDAQAB";//Value to be replaced by service

            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(base64EncodedPublicKey.getBytes(StandardCharsets.UTF_8)));
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

//Step 2.1: Generate Key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = new SecretKeySpec(Hex.decode("14B784F0F287070F962F8A24A854CEC0AF3BC73C2358C3F6D1CA5992FC59AB61"), "AES"); //Value to be replaced by keyGen.generateKey();

//Step 2.2: Encrypt Key
            Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_SPEC);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            String encryptedKey = Hex.toHexString(rsaCipher.doFinal(aesKey.getEncoded()));

            byte[] aesKeyForEncryption = aesKey.getEncoded();
            System.out.println(Arrays.toString(aesKeyForEncryption));

            //this would be used in below Step 3 when requesting the encrypted data
            Hex.toHexString(rsaCipher.doFinal(aesKey.getEncoded()));

            String formattedToken = "4" + TOKEN + "000000000000000";
            byte[] formattedTokenBytes = hexStringToByteArray(formattedToken);

            String newPinBlock = "44" + NEW_PIN + "AAAAAAAAAA" + RANDOM_HEX_STRING;
            byte[] newPinBlockBytes = hexStringToByteArray(newPinBlock);

            //encrypt pin
            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_SPEC);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
            byte[] encryptedPinBlock = aesCipher.doFinal(newPinBlockBytes);

            //combine it with the formatted token
            byte[] xorResult = xorByteArrays(encryptedPinBlock, formattedTokenBytes);

            byte[] encryptedPayload = aesCipher.doFinal(xorResult);
            String encryptedPayloadHex = Hex.toHexString(encryptedPayload);


            URL url = new URL(PINS_CHANGE_ENDPOINT);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("x-api-key", BALANCE_API_KEY);
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Accept", "application/json");
            con.setDoOutput(true);

            String body = "{" +
                    "    \"paymentInstrumentId\":\"" + PAYMENT_INSTRUMENT_ID + "\"," +
                    "    \"encryptedKey\":\"" + encryptedKey + "\",\n" +
                    "    \"token\":\"" + TOKEN + "\"," +
                    "    \"encryptedPinBlock\":\"" + encryptedPayloadHex + "\"" +
                    "}";
            System.out.println(body);
            try(OutputStream os = con.getOutputStream()) {
                byte[] input = body.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            StringBuilder resultDataRaw = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(con.getInputStream()))) {
                for (String line; (line = reader.readLine()) != null; ) {
                    resultDataRaw.append(line);
                }
            }
            JSONObject response = new JSONObject(resultDataRaw.toString());

            String status = response.getString("status");

            Assertions.assertTrue(status.matches("completed"), "Status is not completed");

        } catch (NoSuchAlgorithmException e) {
            // HmacSHA256 should be supported
        } catch (InvalidKeyException e) {
            // The key is invalid
        } catch (NoSuchPaddingException | IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException | InvalidAlgorithmParameterException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testPinChange() throws FileNotFoundException {
        final String AES_CIPHER_SPEC = "AES/CBC/NoPadding";
        String formattedToken = "48374188662676926000000000000000";
        String newPinBlock = "441234AAAAAAAAAA2104CFB1E5B1E9F6";

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");

            keyGen.init(256);
            SecretKey aesKey = new SecretKeySpec(Hex.decode("14B784F0F287070F962F8A24A854CEC0AF3BC73C2358C3F6D1CA5992FC59AB61"), "AES");

            byte[] formattedTokenBytes = hexStringToByteArray(formattedToken);
            byte[] newPinBlockBytes = hexStringToByteArray(newPinBlock);

            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_SPEC);

            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
            byte[] encryptedPinBlock = aesCipher.doFinal(newPinBlockBytes);

            byte[] xorResult = xorByteArrays(encryptedPinBlock, formattedTokenBytes);

            byte[] encryptedPayload = aesCipher.doFinal(xorResult);
            String encryptedPayloadHex = Hex.toHexString(encryptedPayload);

            System.out.println(encryptedPayloadHex);

            Cipher aesCipherDecrypt = Cipher.getInstance(AES_CIPHER_SPEC);
            aesCipherDecrypt.init(Cipher.DECRYPT_MODE,aesKey, new IvParameterSpec(new byte[16]));
            byte[] decryptedData = aesCipherDecrypt.doFinal(Hex.decode(encryptedPayloadHex));

            byte[] xorResultDecrypt = xorByteArrays(formattedTokenBytes, decryptedData);
            byte[] decryptedPin = aesCipherDecrypt.doFinal(xorResultDecrypt);
            String decryptedHex = Hex.toHexString(decryptedPin);

            System.out.println("Decrypted Pin: " + decryptedHex);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }

    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static byte[] xorByteArrays(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length];
        for (int i = 0; i < array1.length; i++) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }
        return result;
    }


    private static String generateRandom16DigitNumber() {
        Random random = new Random();
        StringBuilder number = new StringBuilder();

        for (int i = 0; i < 16; i++) {
            int digit = random.nextInt(9) + 1; // Ensures digit is between 1 and 9
            number.append(digit);
        }

        return number.toString();
    }

    public static String generateRandom16Hex() {
        Random random = new Random();
        StringBuilder hexString = new StringBuilder();

        for (int i = 0; i < 16; i++) {
            int hexDigit = random.nextInt(16); // Generates a number between 0 and 15
            hexString.append(Integer.toHexString(hexDigit).toUpperCase()); // Convert to hex and uppercase
        }

        return hexString.toString();
    }

}
