
package com.android.keychain;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.security.CryptOracle.StringAliasNotFoundException;
import android.security.ICryptOracleService;
import android.security.KeyChain;
import android.security.KeyStore;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.MessageFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Kjell Braden <kjell.braden@stud.tu-darmstadt.de>
 */
public class CryptOracleService extends Service {
    private final class BCX509Provider extends Provider {
        private static final long serialVersionUID = -4762217168644088168L;

        private BCX509Provider() {
            super("BCX509", 1, "custom BC provider providing X509 KeyFactory");

            addService(
                    "KeyFactory",
                    "X509",
                    com.android.org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory.class
                            .getCanonicalName());
        }

        private void addService(String type, String algo, String className) {
            setProperty(type + "." + algo, className);
            putService(new Provider.Service(this, type, algo, className, null,
                    null));
        }
    }

    public static final String DEFAULT_PROVIDER = "BC";
    private static final String TAG = "KeyChain";

    public static final String PREFIX_COMMON = "CO_";
    public static final String USER_SYMKEY = PREFIX_COMMON + "USRSKEY_";
    public static final String USER_CERTIFICATE = PREFIX_COMMON + "USRCERT_";
    public static final String USER_PRIVATE_KEY = PREFIX_COMMON + "USRPKEY_";

    private final Provider bcX509Provider = new BCX509Provider();

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
        public byte[] decryptData(String alias, String algorithm, String padding,
                byte[] encryptedData, byte[] iv) throws RemoteException {
            Key key = getKey(alias, algorithm, true);

            try {
                return doCrypt(Cipher.DECRYPT_MODE, key, padding, encryptedData, iv);
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        @Override
        public void deleteSymmetricKey(String alias) throws RemoteException {
            if (!checkGrant(alias))
                throw suppressedRemoteException(new StringAliasNotFoundException());

            this.mKeyStore.delete(USER_SYMKEY + alias);
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
         * @throws InvalidAlgorithmParameterException 
         */
        private byte[] doCrypt(int mode, Key key, String padding, byte[] data, byte[] iv)
                throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

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
                Cipher c = Cipher.getInstance(algorithm, DEFAULT_PROVIDER);

                Log.v(TAG, "init cipher");
                if (iv != null) {
                    c.init(mode, key, new IvParameterSpec(iv));
                } else 
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
            } catch (NoSuchProviderException e) {
                throw new IllegalArgumentException("default provider "
                        + DEFAULT_PROVIDER + " unavailable!");
            }
        }

        @Override
        public byte[] encryptData(String alias, String algorithm, String padding, byte[] plainData,
                byte[] iv) throws RemoteException {
            Key key = getKey(alias, algorithm, false);
            try {
                return doCrypt(Cipher.ENCRYPT_MODE, key, padding, plainData, iv);
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            } catch (RuntimeException e) {
                throw suppressedRemoteException(e);
            }
        }

        @Override
        public void generateSymmetricKey(String alias, String algorithm,
                int keysize) throws RemoteException {
            if (isUsedAlias(alias))
                throw suppressedRemoteException(new IllegalArgumentException(
                        "alias in use"));

            try {
                KeyGenerator gen = KeyGenerator.getInstance(algorithm,
                        DEFAULT_PROVIDER);
                gen.init(keysize);
                SecretKey key = gen.generateKey();

                setGrant(alias);
                this.mKeyStore.put(USER_SYMKEY + alias, key.getEncoded());
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        private Key getKey(String alias, String algorithm, boolean encrypt) throws RemoteException {
            if (isPK(alias))
                if (encrypt)
                    return getPrivKey(alias);
                else
                    return getPubCert(alias).getPublicKey();
            if (isSecret(alias))
                return getSecretKey(alias, algorithm);
            throw suppressedRemoteException(new StringAliasNotFoundException());
        }

        private PrivateKey getPrivKey(String alias) throws RemoteException {
            if (!checkGrant(alias) || !isPK(alias))
                throw suppressedRemoteException(new StringAliasNotFoundException());

            byte[] encodedKey = this.mKeyStore.get(USER_PRIVATE_KEY + alias);
            if (encodedKey == null)
                throw suppressedRemoteException(new StringAliasNotFoundException());

            try {
                return KeyFactory.getInstance("X509",
                        CryptOracleService.this.bcX509Provider)
                        .generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        private Certificate getPubCert(String alias) throws RemoteException {
            if (!checkGrant(alias) || !isPK(alias))
                throw suppressedRemoteException(new StringAliasNotFoundException());

            byte[] byteCert = this.mKeyStore.get(USER_CERTIFICATE + alias);
            if (byteCert == null)
                throw suppressedRemoteException(new StringAliasNotFoundException());

            try {
                CertificateFactory certFactory = CertificateFactory
                        .getInstance("X.509", DEFAULT_PROVIDER);
                Certificate cert = certFactory
                        .generateCertificate(new ByteArrayInputStream(byteCert));
                return cert;
            } catch (NoSuchProviderException e) {
                throw suppressedRemoteException(new IllegalArgumentException(
                        "default provider " + DEFAULT_PROVIDER
                                + " unavailable!"));
            } catch (CertificateException e) {
                throw suppressedRemoteException(e);
            }
        }

        private SecretKey getSecretKey(String alias, String algorithm)
                throws RemoteException {
            if (!checkGrant(alias) || !isSecret(alias))
                throw suppressedRemoteException(new StringAliasNotFoundException());

            byte[] encodedKey = this.mKeyStore.get(USER_SYMKEY + alias);
            if (encodedKey == null)
                throw suppressedRemoteException(new StringAliasNotFoundException());

            try {
                return new SecretKeySpec(encodedKey, algorithm);
            } catch (IllegalArgumentException e) {
                throw suppressedRemoteException(e);
            }
        }

        @Override
        public void importSymmetricKey(String alias, byte[] key)
                throws RemoteException {
            if (isUsedAlias(alias))
                throw suppressedRemoteException(new IllegalArgumentException(
                        "alias in use"));

            setGrant(alias);
            this.mKeyStore.put(USER_SYMKEY + alias, key);
        }

        private boolean isPK(String alias) {
            return this.mKeyStore.contains(USER_CERTIFICATE + alias);
        }

        private boolean isSecret(String alias) {
            return this.mKeyStore.contains(USER_SYMKEY + alias);
        }

        private boolean isUsedAlias(String alias) {
            return isSecret(alias) || isPK(alias);
        }

        @Override
        public byte[] mac(String alias, String algorithm, byte[] data)
                throws RemoteException {
            SecretKey key = getSecretKey(alias, algorithm);

            if (algorithm == null)
                throw new IllegalArgumentException(
                        "key unusable - unknown algorithm");
            try {
                Log.v(TAG, "loading mac");
                Mac m = Mac.getInstance(algorithm, DEFAULT_PROVIDER);

                Log.v(TAG, "init mac");
                m.init(key);
                Log.v(TAG, "running mac");
                byte[] processedData = m.doFinal(data);
                Log.v(TAG, "returning result");
                return processedData;
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        @Override
        public byte[] retrieveSymmetricKey(String alias, String algorithm)
                throws RemoteException {
            return getSecretKey(alias, algorithm).getEncoded();
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
        public byte[] sign(String alias, String hashAlgorithm, byte[] data) throws RemoteException {
            try {
                PrivateKey key = getPrivKey(alias);
                String sigAlgo = signatureAlgorithm(hashAlgorithm, key);
                Signature sig = Signature.getInstance(sigAlgo,
                        DEFAULT_PROVIDER);
                sig.initSign(key);
                sig.update(data);
                return sig.sign();
            } catch (GeneralSecurityException e) {
                throw suppressedRemoteException(e);
            }
        }

        @Override
        public void storePublicCertificate(String alias, byte[] pemEncodedCert)
                throws RemoteException {
            if (isUsedAlias(alias))
                throw suppressedRemoteException(new IllegalArgumentException(
                        "alias in use"));

            setGrant(alias);
            this.mKeyStore.put(USER_CERTIFICATE + alias, pemEncodedCert);
        }

        private RemoteException suppressedRemoteException(Throwable e) {
            RemoteException re = new RemoteException();
            Log.w(TAG, "caught exception", e);
            re.addSuppressed(e);
            return re;
        }

        @Override
        public boolean verify(String alias, String hashAlgorithm, byte[] data, byte[] signature)
                throws RemoteException {
            try {
                Certificate cert = getPubCert(alias);
                String sigAlgo = signatureAlgorithm(hashAlgorithm, cert.getPublicKey());
                Signature sig = Signature.getInstance(sigAlgo,
                        DEFAULT_PROVIDER);
                sig.initVerify(cert);
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

    protected String signatureAlgorithm(String hashAlgorithm, Key key) throws InvalidKeyException {
        String keyAlgo = key.getAlgorithm();
        if ("RSA".equals(keyAlgo))
            return hashAlgorithm + "withRSA";
        if ("DSA".equals(keyAlgo))
            return hashAlgorithm + "withDSA";
        if ("EC".equals(keyAlgo) || "ECDSA".equals(keyAlgo))
            return hashAlgorithm + "withECDSA";

        throw new InvalidKeyException("signing with key algorithm=" + keyAlgo + " not implemented");
    }
}
