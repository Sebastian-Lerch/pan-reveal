import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class TestPinReveal {

    @Test
    public void testKeyGenerationFullyAutomated(){
        /*
        Parameters - edit only the following
         */
        final String PAYMENT_INSTRUMENT_ID = "<YOUR Payment instrument id here>";
        final String BALANCE_API_KEY = "<YOUR API KEY here>";
        /*
        End Parameters
         */
        final String AES_CIPHER_SPEC = "AES/CBC/NoPadding";
        final String RSA_CIPHER_SPEC = "RSA/NONE/PKCS1Padding";
        final String PUBLIC_KEY_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/publicKey?purpose=pinReveal";
        final String REVEAL_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/pins/reveal";
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
//            SecretKey aesKey = new SecretKeySpec(Hex.decode("14B784F0F287070F962F8A24A854CEC0AF3BC73C2358C3F6D1CA5992FC59AB61"), "AES");
            SecretKey aesKey = keyGen.generateKey();

//Step 2.2: Encrypt Key
            Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_SPEC);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            String encryptedKey = Hex.toHexString(rsaCipher.doFinal(aesKey.getEncoded()));

//Step 3: Request encrypted data
            StringBuilder encryptedDataRaw = new StringBuilder();

            URL url = new URL(REVEAL_ENDPOINT);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("x-api-key", BALANCE_API_KEY);
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Accept", "application/json");
            con.setDoOutput(true);
            String body = "{\"paymentInstrumentId\": \"" + PAYMENT_INSTRUMENT_ID + "\", \"encryptedKey\": \"" + encryptedKey + "\"}";
            try(OutputStream os = con.getOutputStream()) {
                byte[] input = body.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(con.getInputStream()))) {
                for (String line; (line = reader.readLine()) != null; ) {
                    encryptedDataRaw.append(line);
                }
            }
            JSONObject encryptedDataJson = new JSONObject(encryptedDataRaw.toString());

            String encryptedPinBlock = encryptedDataJson.getString("encryptedPinBlock");
            String token = encryptedDataJson.getString("token");

//Step 4.1: Decrypt encrypted data
            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_SPEC);
            aesCipher.init(Cipher.DECRYPT_MODE,aesKey, new IvParameterSpec(new byte[16]));
            byte[] decryptedData = aesCipher.doFinal(Hex.decode(encryptedPinBlock));
            System.out.println("Decrypted data: " + Arrays.toString(decryptedData));
//4.2 format token
            String formattedHex = "4" + token + "000000000000000";
            System.out.println("Formatted Hex String: " + formattedHex);

            byte[] byteArray = hexStringToByteArray(formattedHex);

            System.out.print("Byte Array: ");
            for (byte b : byteArray) {
                System.out.printf("%02X ", b);
            }
            System.out.print("\n");
//4.3 combine formatted token and decrypted pin block using XOR
            byte[] xorResult = xorByteArrays(byteArray, decryptedData);

            // Display the byte array
            System.out.print("XOR Byte Array: ");
            for (byte b : xorResult) {
                System.out.printf("%02X ", b);
            }
            System.out.print("\n");
            //4.4 decrypt the result using RSA
            byte[] decryptedPin = aesCipher.doFinal(xorResult);
            String decryptedHex = Hex.toHexString(decryptedPin);
            System.out.println("Decrypted Pin: " + decryptedHex);

            //4.5 extract the PIN
            if (decryptedHex.length() >= 4) {
                String extractedDigits = decryptedHex.substring(1, 5);
                System.out.println("Extracted Digits: " + extractedDigits);

                Assertions.assertTrue(extractedDigits.matches("\\d{4}"), "Extracted value is not a 4-digit number");
            } else {
                System.out.println("Decrypted Hex String is too short to extract digits 1-4.");
            }

        } catch (NoSuchAlgorithmException e) {
            // HmacSHA256 should be supported
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            // The key is invalid
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 InvalidKeySpecException | BadPaddingException | IOException e) {
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
        final String RSA_CIPHER_SPEC = "RSA/NONE/PKCS1Padding";

        try {
            Security.addProvider(new BouncyCastleProvider());

//Step 1: Get public key
            String base64EncodedPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtQs4ZLCWIIZ1Oq0/GWDjFR0hi8sibr2TscHQL0iCTRLGpyxzPx/KTWo83GlebhP8xoAGych3bixUKy25bko2h+/R75bix3O2/YGZy3JqhiTj1uIsn4RJRwguORPvfodddH2OkeSBDFdseOGqgMChZo0sC/Onq/Rf6og1jtxq9fGxrWaKTPfVngfXoHNQ+AyYUp0LJQtWooQMNXEQuE7NK/3Q6cKX6InoQw087Mk5ZiSdB2ijIYcdrfaF/UGKtESCUnHhCr5zyPz/F2EorwyFA369xanxdn8msLOuKWsX0AFNN6ppH10/c4YuhFgnNEjNOQnBYOr1NdKiqE4WJ3grwIDAQAB";//Value to be replaced by service
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(base64EncodedPublicKey.getBytes(StandardCharsets.UTF_8)));
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

//Step 2.1: Generate Key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = new SecretKeySpec(Hex.decode("14B784F0F287070F962F8A24A854CEC0AF3BC73C2358C3F6D1CA5992FC59AB61"), "AES"); //Value to be replaced by keyGen.generateKey();

//Step 2.2: Encrypt Key
            Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_SPEC);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            //this would be used in below Step 3 when requesting the encrypted data
            Hex.toHexString(rsaCipher.doFinal(aesKey.getEncoded()));

//Step 3: Request encrypted data
            //let's proceed with some already dummy data
            String encryptedData = "2F93F6F3D6ECA6192F71BBA3D99BD825"; //Value to be replaced by service
            String token = "8661218353725212";

//Step 4.1: Decrypt encrypted data
            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_SPEC);
            aesCipher.init(Cipher.DECRYPT_MODE,aesKey, new IvParameterSpec(new byte[16]));
            byte[] decryptedData = aesCipher.doFinal(Hex.decode(encryptedData));

            String formattedHex = "4" + token + "000000000000000";
            System.out.println("Formatted Hex String: " + formattedHex);

            byte[] byteArray = hexStringToByteArray(formattedHex);

            System.out.print("Byte Array: ");
            for (byte b : byteArray) {
                System.out.printf("%02X ", b);
            }
            System.out.print("\n");
//4.3 combine formatted token and decrypted pin block using XOR
            byte[] xorResult = xorByteArrays(byteArray, decryptedData);

            // Display the byte array
            System.out.print("XOR Byte Array: ");
            for (byte b : xorResult) {
                System.out.printf("%02X ", b);
            }
            System.out.print("\n");
            //4.4 decrypt the result using RSA
            byte[] decryptedPin = aesCipher.doFinal(xorResult);
            String decryptedHex = Hex.toHexString(decryptedPin);
            System.out.println("Decrypted Pin: " + decryptedHex);

            //4.5 extract the PIN
            if (decryptedHex.length() >= 4) {
                String extractedDigits = decryptedHex.substring(1, 5);
                System.out.println("Extracted Digits: " + extractedDigits);

                Assertions.assertTrue(extractedDigits.matches("\\d{4}"), "Extracted value is not a 4-digit number");
            } else {
                System.out.println("Decrypted Hex String is too short to extract digits 1-4.");
            }

        } catch (NoSuchAlgorithmException e) {
            // HmacSHA256 should be supported
        } catch (InvalidKeyException e) {
            // The key is invalid
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 InvalidKeySpecException | BadPaddingException e) {
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

}
