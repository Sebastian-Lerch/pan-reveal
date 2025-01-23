# pan-reveal
This repository can be used to test the end to end flow of the PAN reveal process of an Adyen Issuing integration. The full process is described in the [Adyen docs](https://docs.adyen.com/issuing/manage-card-data/reveal-card-details/).

## Usage
There are two ways you can use this repo. 
### Fully automated flow
If you configured the parameters outlined below you can automatically test whether your credential is able to reveal the PAN of a card.
For this simply execute the unit test `testKeyGenerationFullyAutomated`.

You only need two parameters, everything else works out of the box. These have to be configured at the top of `TestPanReveal.java`
1. PAYMENT_INSTRUMENT_ID: The ID of the PaymentInstrument (aka Card) you want to reveal the PAN for. E.g. PI3293G223227F5KN6H6PGMLJ
2. BALANCE_API_KEY: The API key of your BCL credential. Make sure that this credential has the role **Bank Issuing PaymentInstrument Reveal Webservice role**. If you cannot assign this role to your API user reach out to your Adyen contact.

### Manual flow
If you already have some values you want to check if they work you can use the unit test `testKeyGenerationWorkingSampleManual`.
Here you have to configure everything manually like adding the public key, etc. This is useful if you doubt whether the values you have are working or not.

1. First get the public key in your preferred way. Then paste it into `base64EncodedPublicKey`.
2. Take the output of `Hex.toHexString(rsaCipher.doFinal(aesKey.getEncoded()));` and get the encrypted data from the Adyen server and put it into `encryptedData`.
3. Take the value from `paymentInstrumentData` and compare it with the real PAN of the card.

Note that there are some sample values in the source which can only be treated as examples and **NEVER HARDCODE THE AES KEY**.
