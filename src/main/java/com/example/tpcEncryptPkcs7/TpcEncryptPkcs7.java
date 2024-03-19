package com.example.tpcEncryptPkcs7;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.encoders.Hex;

public class TpcEncryptPkcs7 {

    private static final String DATA_TO_ENCRYPT = "{\"fpan\":\"987654321123456789\",\"issuerCardRefId\":\"abc1245784219\",\"exp\":\"1223\",\"cardholderName\":\"John\""
            + ",\"postalAddress\":{\"line1\":\"address1\",\"line2\":\"address2\",\"city\":\"City1\",\"postalCode\":\"12345\",\"state\":\"state1\",\"country\":\"Country1\"}}";

    private static final String KEY_IDENTIFIER = "a_key_id";

    private static final BouncyCastleProvider bcProvider;
    private static PrivateKey privKey;
    private static PublicKey pubKey;

    static {
        bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
    }

    public static void main(String[] args) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        privKey = kp.getPrivate();
        pubKey = kp.getPublic();

        // Encrypt
        byte[] encData = encryptPKCS7(DATA_TO_ENCRYPT.getBytes("UTF-8"), pubKey);
        System.out.println("Encrypted data = " + Hex.toHexString(encData));

        // Decrypt
        byte[] result = decryptPKCS7(encData, privKey);
        System.out.println("Decrypted data = " + new String(result));

    }

    private static byte[] encryptPKCS7(byte[] plainData, PublicKey pubKey) throws Exception {

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();

        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
        OAEPParameterSpec oaepParamSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        AlgorithmIdentifier algoId = paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, oaepParamSpec);

        JceKeyTransRecipientInfoGenerator recipInfo = new JceKeyTransRecipientInfoGenerator(KEY_IDENTIFIER.getBytes(), algoId, pubKey)
                .setProvider(bcProvider);

        gen.addRecipientInfoGenerator(recipInfo);

        CMSProcessableByteArray data = new CMSProcessableByteArray(plainData);
        BcCMSContentEncryptorBuilder builder = new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC);

        CMSEnvelopedData enveloped = gen.generate(data, builder.build());

        return enveloped.getEncoded();
    }

    private static byte[] decryptPKCS7(byte[] encryptedData, PrivateKey privKey) throws Exception {
        CMSEnvelopedData enveloped = new CMSEnvelopedData(encryptedData);
        Collection<RecipientInformation> recip = enveloped.getRecipientInfos().getRecipients();
        KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation) recip.iterator().next();
        return rinfo.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(bcProvider));
    }

}