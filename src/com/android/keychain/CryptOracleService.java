
package com.android.keychain;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.security.Credentials;
import android.security.CryptOracle.StringAliasNotFoundException;
import android.security.ICryptOracleService;
import android.security.KeyChain;
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
import java.security.Signature;
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
public class CryptOracleService extends Service {
    private static final String TAG = "KeyChain";

    private final ICryptOracleService.Stub mICryptOracleService = new ICryptOracleService.Stub() {
        private final KeyStore mKeyStore = KeyStore.getInstance();

        private boolean checkGrant(String alias) throws RemoteException {
            final int uid = getCallingUid();
            long token = clearCallingIdentity();

            Log.d(TAG, "checking grant for " + uid + " to " + alias);

            KeyChain.KeyChainConnection connection = null;
            try {
                connection = KeyChain.bind(CryptOracleService.this);
                return connection.getService().hasGrant(uid, alias);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                Log.d(TAG, "interrupted while granting access", ignored);
                return false;
            } finally {
                if (connection != null)
                    connection.close();
                restoreCallingIdentity(token);
            }
        }

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
                    MessageFormat.format(
                            "doCrypt({0}, keyformat={1}, padding={2}, datalen={3})",
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

            try {
                PublicKey pubKey = getPubCert(alias).getPublicKey();

                return doCrypt(Cipher.ENCRYPT_MODE, pubKey, padding, plainData);
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            } catch (RuntimeException e) {
                throw suppressedRemoteException(e);
            }
        }

        private PrivateKey getPrivKey(String alias) throws RemoteException {
            if (!checkGrant(alias))
                throw suppressedRemoteException(new StringAliasNotFoundException());

            byte[] encodedKey = this.mKeyStore.get(Credentials.USER_PRIVATE_KEY + alias);
            if (encodedKey == null)
                throw suppressedRemoteException(new StringAliasNotFoundException());

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

        private Certificate getPubCert(String alias) throws RemoteException {
            if (!checkGrant(alias))
                throw suppressedRemoteException(new StringAliasNotFoundException());

            byte[] byteCert = this.mKeyStore.get(Credentials.USER_CERTIFICATE + alias);
            if (byteCert == null)
                throw suppressedRemoteException(new StringAliasNotFoundException());

            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(
                        byteCert));
                return cert;
            } catch (CertificateException e) {
                throw suppressedRemoteException(e);
            }
        }

        private void setGrant(String alias) throws RemoteException {
            final int uid = getCallingUid();
            long token = clearCallingIdentity();

            Log.d(TAG, "setting grant for " + uid + " to " + alias);

            KeyChain.KeyChainConnection connection = null;
            try {
                connection = KeyChain.bind(CryptOracleService.this);
                connection.getService().setGrant(uid, alias, true);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                Log.d(TAG, "interrupted while granting access", ignored);
            } finally {
                if (connection != null)
                    connection.close();
                restoreCallingIdentity(token);
            }
        }

        @Override
        public byte[] sign(String alias, String algorithm, byte[] data) throws RemoteException {
            try {
                Signature sig = Signature.getInstance(algorithm);
                sig.initSign(getPrivKey(alias));
                sig.update(data);
                return sig.sign();
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        @Override
        public void storePublicCertificate(String alias, byte[] pemEncodedCert)
                throws RemoteException {
            setGrant(alias);
            this.mKeyStore.put(Credentials.USER_CERTIFICATE + alias, pemEncodedCert);
        }

        private RemoteException suppressedRemoteException(Throwable e) {
            RemoteException re = new RemoteException();
            Log.w(TAG, "caught exception", e);
            re.addSuppressed(e);
            return re;
        }

        @Override
        public boolean verify(String alias, String algorithm, byte[] data, byte[] signature)
                throws RemoteException {
            try {
                Signature sig = Signature.getInstance(algorithm);
                sig.initVerify(getPubCert(alias));
                sig.update(data);
                return sig.verify(signature);
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return this.mICryptOracleService;
    }
}
