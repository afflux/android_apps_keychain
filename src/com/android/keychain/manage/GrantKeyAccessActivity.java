
package com.android.keychain.manage;

import android.app.Activity;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.RemoteException;
import android.security.CryptOracle;
import android.security.IKeyChainService;
import android.security.KeyChain;
import android.security.KeyStore;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.android.keychain.CryptOracleService;
import com.android.keychain.R;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class GrantKeyAccessActivity extends Activity {
    private abstract class GrantTask extends AsyncTask<Void, Void, Boolean> {
        private final boolean cancelActivityOnFail;

        private final KeyStore mKeyStore = KeyStore.getInstance();
        private final KeyFactory mKeyFact;
        private final CertificateFactory mCertFact;

        public GrantTask(boolean cancelActivityOnFail) throws NoSuchAlgorithmException,
                CertificateException, NoSuchProviderException {
            this.cancelActivityOnFail = cancelActivityOnFail;
            this.mKeyFact = KeyFactory.getInstance("X509", CryptOracle.bcX509Provider);
            this.mCertFact = CertificateFactory.getInstance("X.509",
                    CryptOracleService.DEFAULT_PROVIDER);
        }

        private final ProgressDialog pd = new ProgressDialog(GrantKeyAccessActivity.this);

        @Override
        protected Boolean doInBackground(Void... params) {
            KeyChain.KeyChainConnection connection = null;
            try {
                connection = KeyChain.bind(GrantKeyAccessActivity.this);
                if (!runOperation(connection.getService(), mSenderUid, mAlias))
                    return false;

                return checkType();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                Log.e(TAG, "interrupted while doing grant stuff", ignored);
            } finally {
                if (connection != null)
                    connection.close();
            }

            return false;
        }

        private boolean checkType() {
            Key pk;
            switch (mType) {
                case PRIVATE_SIGN:
                    pk = loadKey(true);
                    if (pk == null)
                        return false;

                    return canSignVerify(pk.getAlgorithm());
                case PRIVATE_DECRYPT:
                    pk = loadKey(true);
                    if (pk == null)
                        return false;

                    return canDecryptEncrypt(pk.getAlgorithm());
                case PUBLIC_VERIFY:
                    pk = loadKey(false);
                    if (pk == null)
                        return false;

                    return canSignVerify(pk.getAlgorithm());
                case PUBLIC_ENCRYPT:
                    pk = loadKey(false);
                    if (pk == null)
                        return false;

                    return canDecryptEncrypt(pk.getAlgorithm());
                case SECRET:
                    return this.mKeyStore.contains(CryptOracleService.USER_SYMKEY + mAlias);
                case AGREEMENT:
                    pk = loadKey(false);
                    if (pk == null)
                        return false;

                    return canAgree(pk.getAlgorithm());
                default:
                    return false;
            }
        }

        private Key loadKey(boolean priv) {
            byte[] encoded = this.mKeyStore.get((priv ? CryptOracleService.USER_PRIVATE_KEY
                    : CryptOracleService.USER_CERTIFICATE) + mAlias);
            if (encoded == null)
                return null;

            try {
                if (priv)
                    return mKeyFact.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                else {
                    return mCertFact.generateCertificate(new ByteArrayInputStream(encoded))
                            .getPublicKey();
                }
            } catch (InvalidKeySpecException e) {
                return null;
            } catch (CertificateException e) {
                return null;
            }
        }

        private boolean canSignVerify(String algorithm) {
            return !"DH".equals(algorithm) && !"ECDH".equals(algorithm);
        }

        private boolean canAgree(String algorithm) {
            return !canSignVerify(algorithm);
        }

        private boolean canDecryptEncrypt(String algorithm) {
            return "RSA".equals(algorithm);
        }

        protected abstract boolean runOperation(IKeyChainService service, int mSenderUid,
                String mAlias);

        @Override
        protected void onPostExecute(Boolean result) {
            pd.dismiss();

            if (result)
                finish(Activity.RESULT_OK);
            else if (cancelActivityOnFail)
                finish(Activity.RESULT_CANCELED);
        }

        @Override
        protected void onPreExecute() {
            pd.setIndeterminate(true);
            pd.setCancelable(false);
            pd.show();
        }
    }

    private static final String TAG = "GrantKeyAccess";
    private PendingIntent mSender;
    private int mSenderUid;
    private String mAlias;
    private CryptOracle.UsageType mType;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.grant_access_dialog);

        Button b = (Button) findViewById(R.id.deny_button);
        b.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                finish(Activity.RESULT_CANCELED);
            }
        });

        b = (Button) findViewById(R.id.allow_button);
        b.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                grant();
            }
        });

    }

    private void checkGrant() {
        try {
            new GrantTask(false) {
                @Override
                protected boolean runOperation(IKeyChainService service, int mSenderUid,
                        String mAlias) {
                    try {
                        return service.hasGrant(mSenderUid, mAlias);
                    } catch (RemoteException e) {
                        Log.e(TAG, "checking key access failed", e);
                        return false;
                    }
                }
            }.execute();
        } catch (GeneralSecurityException e) {
            Log.e(TAG, "could not create granttask", e);
        }
    }

    protected void grant() {
        Log.d(TAG, "setting grant for " + mSenderUid + " to " + mAlias);

        try {
            new GrantTask(true) {
                @Override
                protected boolean runOperation(IKeyChainService service, int mSenderUid,
                        String mAlias) {
                    try {
                        service.setGrant(mSenderUid, mAlias, true);
                        return true;
                    } catch (RemoteException e) {
                        Log.e(TAG, "checking key access failed", e);
                        return false;
                    }
                }
            }.execute();
        } catch (GeneralSecurityException e) {
            Log.e(TAG, "could not create granttask", e);
        }
    }

    protected void finish(int result) {
        setResult(result);
        finish();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void onResume() {
        super.onResume();

        mAlias = getIntent().getStringExtra(CryptOracle.EXTRA_ALIAS);
        mType = (CryptOracle.UsageType) getIntent().getSerializableExtra(CryptOracle.EXTRA_TYPE);
        mSender = getIntent().getParcelableExtra(KeyChain.EXTRA_SENDER);
        if (mSender == null) {
            // if no sender, bail, we need to identify the app to the user
            // securely.
            finish(Activity.RESULT_CANCELED);
            return;
        }
        try {
            mSenderUid = getPackageManager().getPackageInfo(
                    mSender.getIntentSender().getTargetPackage(), 0).applicationInfo.uid;
        } catch (PackageManager.NameNotFoundException e) {
            // if unable to find the sender package info bail,
            // we need to identify the app to the user securely.
            finish(Activity.RESULT_CANCELED);
            return;
        }

        checkGrant();

        TextView descView = (TextView) findViewById(R.id.grant_description);

        String pkg = mSender.getIntentSender().getTargetPackage();
        PackageManager pm = getPackageManager();
        CharSequence applicationLabel;
        try {
            applicationLabel = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString();
        } catch (PackageManager.NameNotFoundException e) {
            applicationLabel = pkg;
        }

        descView.setText(getString(R.string.key_requesting_app, applicationLabel, mAlias));
    }
}
