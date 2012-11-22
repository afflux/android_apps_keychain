
package com.android.keychain;

import android.app.IntentService;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.security.Credentials;
import android.security.ICryptOracleService;
import android.security.KeyStore;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.MessageFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author Kjell Braden <kjell.braden@stud.tu-darmstadt.de>
 */
public class CryptOracleService extends IntentService {
    private static final String TAG = "KeyChain";

    private final ICryptOracleService.Stub mICryptOracleService = new ICryptOracleService.Stub() {
        private final KeyStore mKeyStore = KeyStore.getInstance();

        @Override
        public byte[] decryptData(String alias, String padding, byte[] encryptedData)
                throws RemoteException {
            PrivateKey privKey = getPrivKey(alias);

            try {
                return doCrypt(Cipher.DECRYPT_MODE, privKey, padding, encryptedData);
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        /**
         * helper method for cipher operations, ie. en- and decrypting.
         * 
         * @param mode {@link Cipher#ENCRYPT_MODE} or
         *            {@link Cipher#DECRYPT_MODE}
         * @param key a public or private key, depending on our mode
         * @param padding mode of operation and padding specification, as in
         *            {@link Cipher#getInstance(String)}
         * @param data
         * @return processed data
         * @throws NoSuchPaddingException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         */
        private byte[] doCrypt(int mode, Key key, String padding, byte[] data)
                throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

            Log.d(TAG,
                    MessageFormat.format("doCrypt({0}, keyformat={1}, padding={2}, datalen={3})",
                            mode,
                            key.getAlgorithm(), padding, data.length));
            String algorithm = key.getAlgorithm();

            if (algorithm == null)
                throw new IllegalArgumentException("key unusable - unknown algorithm");
            if (padding != null)
                algorithm += "/" + padding;

            try {
                Log.v(TAG, "loading cipher");
                Cipher c = Cipher.getInstance(algorithm);

                Log.v(TAG, "init cipher");
                c.init(mode, key);
                Log.v(TAG, "running cipher");
                byte[] processedData = c.doFinal(data);
                Log.v(TAG, "returning result");
                return processedData;
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("key unusable - algorithm \""
                        + key.getAlgorithm() + "\" not supported");
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException("key unusable - algorithm \""
                        + key.getAlgorithm() + "\" not supported");
            }
        }

        @Override
        public byte[] encryptData(String alias, String padding, byte[] plainData)
                throws RemoteException {

            PublicKey pubKey = getPubKey(alias);

            try {
                return doCrypt(Cipher.ENCRYPT_MODE, pubKey, padding, plainData);
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        private PrivateKey getPrivKey(String alias) throws RemoteException {
            byte[] encodedKey = this.mKeyStore.get(Credentials.USER_PRIVATE_KEY + alias);
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(
                        new PKCS8EncodedKeySpec(encodedKey));
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }

            // final OpenSSLEngine engine =
            // OpenSSLEngine.getInstance("keystore");
            // try {
            // return engine.getPrivateKeyById(Credentials.USER_PRIVATE_KEY +
            // alias);
            // } catch (InvalidKeyException e) {
            // throw suppressedRemoteException(e);
            // }
        }

        private PublicKey getPubKey(String alias) throws RemoteException {
            byte[] byteCert = this.mKeyStore.get(Credentials.USER_CERTIFICATE + alias);
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(
                        byteCert));
                return cert.getPublicKey();
            } catch (CertificateException e) {
                throw suppressedRemoteException(e);
            }
        }

        private RemoteException suppressedRemoteException(Throwable e) {
            RemoteException re = new RemoteException();
            Log.w(TAG, "caught exception", e);
            re.addSuppressed(e);
            return re;
        }
    };

    public CryptOracleService() {
        super(CryptOracleService.class.getSimpleName());
    }

    @Override
    public IBinder onBind(Intent intent) {
        return this.mICryptOracleService;
    }

    @Override
    protected void onHandleIntent(Intent intent) {
    }
}
