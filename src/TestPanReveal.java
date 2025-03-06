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

public class TestPanReveal {

    @Test
    public void testKeyGenerationFullyAutomated(){
        /*
        Parameters - edit only the following
         */
        final String PAYMENT_INSTRUMENT_ID = "<YOUR_PAYMENT_INSTRUMENT_ID>";
        final String BALANCE_API_KEY = "<YOUR_API_KEY_HERE>";
        /*
        End Parameters
         */
        final String AES_CIPHER_SPEC = "AES/CBC/PKCS5Padding";
        final String RSA_CIPHER_SPEC = "RSA/NONE/PKCS1Padding";
        final String PUBLIC_KEY_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/publicKey?purpose=panReveal";
        final String REVEAL_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/paymentInstruments/reveal";
        final String GET_REVEAL_ENDPOINT = "https://balanceplatform-api-test.adyen.com/bcl/v2/paymentInstruments/" + PAYMENT_INSTRUMENT_ID +"/reveal";
        try {
            Security.addProvider(new BouncyCastleProvider());
//STEP 0: Get Info of payment instrument to have to possibility to test if the result is correct
            String comparisonData;
            try {
                comparisonData = getRequest(BALANCE_API_KEY, GET_REVEAL_ENDPOINT);
            }
            catch (IOException e){
                //When there is an error in getting the data from the GET /reveal endpoint we end up here
                //This can happen if the BCL API credential does not have the PCI role enabled (which can only be
                //enabled for PCI Compliant card partners in LIVE. In TEST we can enable it, however this would then be
                //a deviation from the live environment.
                comparisonData = "Error";
            }
            //Step 1: Get public key
            String base64EncodedPublicKeyRaw = getRequest(BALANCE_API_KEY, PUBLIC_KEY_ENDPOINT);

            JSONObject jsonObject = new JSONObject(base64EncodedPublicKeyRaw);
            String base64EncodedPublicKey = jsonObject.getString("publicKey");

            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(base64EncodedPublicKey.getBytes(StandardCharsets.UTF_8)));
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

//Step 2.1: Generate Key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();

//Step 2.2: Encrypt Key
            Cipher rsaCipher = Cipher.getInstance(RSA_CIPHER_SPEC);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            //this would be used in below Step 3 when requesting the encrypted data
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

            String encryptedData = encryptedDataJson.getString("encryptedData");

//Step 4.1: Decrypt encrypted data
            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_SPEC);
            aesCipher.init(Cipher.DECRYPT_MODE,aesKey, new IvParameterSpec(new byte[16]));
            byte[] decryptedData = aesCipher.doFinal(Hex.decode(encryptedData));

//4.2 Convert to String
            String paymentInstrumentData = new String(decryptedData, StandardCharsets.UTF_8);
            JSONObject jsonPaymentInstrumentData = new JSONObject(paymentInstrumentData);
// Compare result
            if(comparisonData.equals("Error")){
                //When we could not retrieve the data from the GET /reveal endpoint in STEP 0 we can only do a sanity check
                //which should be good enough
                Assertions.assertTrue(jsonPaymentInstrumentData.has("cvc"));
                Assertions.assertTrue(jsonPaymentInstrumentData.has("pan"));
                Assertions.assertTrue(jsonPaymentInstrumentData.has("expiration"));
            }
            else {
                //We have the real values and can compare the result
                JSONObject jsonComparisonData = new JSONObject(comparisonData);
                Assertions.assertTrue(jsonComparisonData.similar(jsonPaymentInstrumentData));
            }

        } catch (NoSuchAlgorithmException e) {
            // HmacSHA256 should be supported
        } catch (InvalidKeyException e) {
            // The key is invalid
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
        final String AES_CIPHER_SPEC = "AES/CBC/PKCS5Padding";
        final String RSA_CIPHER_SPEC = "RSA/NONE/PKCS1Padding";

        try {
            Security.addProvider(new BouncyCastleProvider());

//Step 1: Get public key
            String base64EncodedPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Yciih2A+4RVLoutFwbVfEhuOc2sFMb3iZKPkL18Kti/q1d7XP/Ep1zSOVP3449Sb+jPgUwxNcUR5Hm2F4bEqnTBCtI/6Zm8k2DOPyhBF1O8sZpNCvMLv8406p0VSs5bsJ5K0HBgw5NTOwFv/38u/roNngrRA1U+le6Hf9IeMlTXY79Dl9xttG0meNk/uNFL5/ozbjEZhpgSXcs47l3zKaU+e2dCmbVQwxlnAaCj1tAOxPPke/bF7Q/KxlgbMrIT80Joyn3F+zcyU4JkeqdIak0vIzz0wbA4GyN5Ano1i53oP6W3hRiE2f9onU6GUWVJbpV09EF1EQB5EVEHy50A8QIDAQAB";//Value to be replaced by service
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
            String encryptedData = "4332F74A329924703EB12A6D5E7D6076D94018073FD3C07B551640D73630C3FBAD84BF7FEB9F7FA8145F83CD3258BEC80B9355B013724B2B661EE21A873F37DA2C170D6A4B15DB0C6CA8033FE65BB57542DF7974E133BADD6F39FCEA049000BF"; //Value to be replaced by service

//Step 4.1: Decrypt encrypted data
            Cipher aesCipher = Cipher.getInstance(AES_CIPHER_SPEC);
            aesCipher.init(Cipher.DECRYPT_MODE,aesKey, new IvParameterSpec(new byte[16]));
            byte[] decryptedData = aesCipher.doFinal(Hex.decode(encryptedData));

//4.2 Convert to String
            String paymentInstrumentData = new String(decryptedData, StandardCharsets.UTF_8);
            Assertions.assertEquals("{\"cvc\":\"607\",\"expiration\":{\"month\":\"12\",\"year\":\"2023\"},\"pan\":\"5168800000001065\"}",paymentInstrumentData);Security.addProvider(new BouncyCastleProvider());

        } catch (NoSuchAlgorithmException e) {
            // HmacSHA256 should be supported
        } catch (InvalidKeyException e) {
            // The key is invalid
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 InvalidKeySpecException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
