
package com.android.keychain;

import android.app.Activity;
import android.app.DialogFragment;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.UserHandle;
import android.security.Credentials;
import android.security.IKeyChainAliasCallback;
import android.security.KeyChain;
import android.security.KeyStore;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.android.org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

/**
 * @author Kjell Braden <kjell.braden@stud.tu-darmstadt.de>
 */
@SuppressWarnings("deprecation")
public class KeyChainGenerateActivity extends Activity {
    /**
     * Key parameter dialog
     */
    private class GenerateDialogFragment extends DialogFragment implements OnClickListener {
        private static final int DEFAULT_KEY_SIZE = 2048;
        private static final int DEFAULT_LIFETIME_YEARS = 5;

        private Spinner algorithmSelector;

        private final DateFormat dateFormat = android.text.format.DateFormat
                .getDateFormat(getApplicationContext());
        private TextView errorView;
        private TextView expiryDateView;
        private TextView keySizeView;
        private TextView nameView;

        public boolean isPowerOfTwo(int n) {
            return ((n & (n - 1)) == 0) && (n > 0);
        }

        @Override
        public void onClick(View v) {
            // read specified values
            String algorithm = (String) this.algorithmSelector.getSelectedItem();
            String alias = this.nameView.getText().toString();
            String keySizeString = this.keySizeView.getText().toString();
            String expiryDateString = this.expiryDateView.getText().toString();

            int keySize;

            try {
                // parse key size
                keySize = Integer.parseInt(keySizeString);
                // verify key size
                // XXX is this necessary?
                if (!isPowerOfTwo(keySize))
                    showError(R.string.invalid_key_size, R.string.invalid_pow2);
            } catch (NumberFormatException e) {
                showError(R.string.invalid_key_size, e.getLocalizedMessage());
                return;
            }

            Date expiryDate;
            try {
                // parse date
                expiryDate = this.dateFormat.parse(expiryDateString);
                if (!expiryDate.after(new Date()))
                    showError(R.string.invalid_date, R.string.invalid_past_date);
            } catch (ParseException e) {
                showError(R.string.invalid_date, e.getLocalizedMessage());
                return;
            }

            try {
                // start key generation in background
                GenerateTask t = new GenerateTask(alias, algorithm, keySize, expiryDate);
                dismiss();
                t.execute();
            } catch (NoSuchAlgorithmException e) {
                showError(R.string.invalid_algorithm, e.getLocalizedMessage());
                return;
            }
        }

        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container,
                Bundle savedInstanceState) {
            View v = inflater.inflate(R.layout.generate_cert_dialog, container, false);

            String appMessage = String.format(getString(R.string.requesting_application),
                    KeyChainGenerateActivity.this.applicationLabel);
            ((TextView) v.findViewById(R.id.app_header)).setText(appMessage);

            this.nameView = (TextView) v.findViewById(R.id.credential_name);
            this.errorView = (TextView) v.findViewById(R.id.error);

            this.algorithmSelector = (Spinner) v.findViewById(R.id.algorithm);
            this.algorithmSelector.setSelection(0);

            this.keySizeView = (TextView) v.findViewById(R.id.key_size);
            this.keySizeView.setText(Integer.toString(DEFAULT_KEY_SIZE));

            Date expiryDate = new Date();
            expiryDate.setYear(expiryDate.getYear() + DEFAULT_LIFETIME_YEARS);

            this.expiryDateView = (TextView) v.findViewById(R.id.expiry_date);
            this.expiryDateView.setText(this.dateFormat.format(expiryDate));

            Button confirm = (Button) v.findViewById(R.id.generate_button);
            confirm.setOnClickListener(this);

            return v;
        }

        private void showError(int errorId, int argId) {
            showError(errorId, getString(argId));
        }

        private void showError(int errorId, Object... args) {
            String msg = getString(errorId, args);
            this.errorView.setText(msg);
            this.errorView.setVisibility(View.VISIBLE);
        }
    }

    private class GenerateTask extends AsyncTask<Void, Integer, Boolean> {

        private final String alias;
        private final Date endDate;
        private final MessageDigest hashAlgorithm;
        private final KeyPairGenerator keyPairGenerator;
        private final ProgressDialog pd = new ProgressDialog(KeyChainGenerateActivity.this);
        private final BigInteger serial;
        private final Date startDate;
        private final X500Principal subject;

        /**
         * @param alias key identifier for use in subsequent operations
         * @param algorithm key algorithm. <i>only RSA supported for now</i>
         * @param keysize
         * @param endDate
         * @param mProgressDialog
         * @see KeyPairGenerator
         * @throws NoSuchAlgorithmException if the given algorithm does not
         *             exist
         */
        public GenerateTask(String alias, String algorithm, int keysize, Date endDate)
                throws NoSuchAlgorithmException {
            this.alias = alias;
            this.endDate = endDate;
            this.subject = new X500Principal("cn=" + alias);
            this.serial = BigInteger.ONE;
            this.startDate = new Date();

            this.hashAlgorithm = MessageDigest.getInstance("MD5");
            this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            this.keyPairGenerator.initialize(keysize);
        }

        /**
         * Largely based on {@link android.security.AndroidKeyPairGenerator}
         * 
         * @throws IllegalStateException if generating the certificate failed
         */
        @Override
        protected Boolean doInBackground(Void... params) throws IllegalStateException {
            publishProgress(R.string.generate_keypair);
            // generate key pair
            KeyPair keyPair = this.keyPairGenerator.genKeyPair();

            PrivateKey privKey = keyPair.getPrivate();
            PublicKey pubKey = keyPair.getPublic();

            this.hashAlgorithm.reset();
            this.hashAlgorithm.update(pubKey.getEncoded());
            String fingerprint = toHexString(this.hashAlgorithm.digest(), ":");
            Log.i(TAG, "generated fingerprint=" + fingerprint);

            // prepate certificate
            final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.setPublicKey(pubKey);
            certGen.setSerialNumber(this.serial);
            certGen.setSubjectDN(this.subject);
            certGen.setIssuerDN(this.subject);
            certGen.setNotBefore(this.startDate);
            certGen.setNotAfter(this.endDate);
            certGen.setSignatureAlgorithm("sha1WithRSA");

            publishProgress(R.string.generate_certificate);
            final X509Certificate cert;
            try {
                // self-sign certificate
                cert = certGen.generate(privKey);
            } catch (Exception e) {
                deleteAllTypesForAlias(this.alias);
                throw new IllegalStateException("Can't generate certificate", e);
            }

            byte[] certBytes;
            try {
                // convert certificate
                certBytes = Credentials.convertToPem(cert);
            } catch (CertificateEncodingException e) {
                deleteAllTypesForAlias(this.alias);
                throw new IllegalStateException("Can't get encoding of certificate", e);
            } catch (IOException e) {
                deleteAllTypesForAlias(this.alias);
                throw new IllegalStateException("Can't get encoding of certificate", e);
            }

            // store
            return KeyChainGenerateActivity.this.mKeyStore.put(Credentials.USER_PRIVATE_KEY
                    + this.alias, privKey.getEncoded())
                    &&
                    KeyChainGenerateActivity.this.mKeyStore.put(Credentials.USER_CERTIFICATE
                            + this.alias, certBytes);
        }

        @Override
        protected void onPostExecute(Boolean result) {
            this.pd.dismiss();
            if (result == true) {
                Toast.makeText(KeyChainGenerateActivity.this,
                        getString(R.string.cert_is_added, this.alias), Toast.LENGTH_LONG).show();
                resultFinish(this.alias);
            } else {
                Toast.makeText(KeyChainGenerateActivity.this,
                        getString(R.string.cert_not_saved, this.alias), Toast.LENGTH_LONG).show();
                resultAbort();
            }
        }

        @Override
        protected void onPreExecute() {
            this.pd.setMessage(getString(R.string.generate_start));
            this.pd.setIndeterminate(true);
            this.pd.setCancelable(false);
            this.pd.show();
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            this.pd.setMessage(getString(values[0]));
        }

        private String toHexString(byte[] bytes, String separator) {
            StringBuilder hexString = new StringBuilder();
            for (byte b : bytes)
                hexString.append(Integer.toHexString(0xFF & b)).append(separator);
            return hexString.toString();
        }

    }

    /**
     * @author Copied from {@link KeyChainActivity}
     */
    private class ResponseSender extends AsyncTask<Void, Void, Void> {
        private final String mAlias;
        private final IKeyChainAliasCallback mKeyChainAliasResponse;

        private ResponseSender(IKeyChainAliasCallback keyChainAliasResponse, String alias) {
            this.mKeyChainAliasResponse = keyChainAliasResponse;
            this.mAlias = alias;
        }

        @Override
        protected Void doInBackground(Void... unused) {
            try {
                if (this.mAlias != null) {
                    KeyChain.KeyChainConnection connection = KeyChain
                            .bind(KeyChainGenerateActivity.this);
                    try {
                        connection.getService().setGrant(KeyChainGenerateActivity.this.mSenderUid,
                                this.mAlias, true);
                    } finally {
                        connection.close();
                    }
                }
                this.mKeyChainAliasResponse.alias(this.mAlias);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                Log.d(TAG, "interrupted while granting access", ignored);
            } catch (Exception ignored) {
                // don't just catch RemoteException, caller could
                // throw back a RuntimeException across processes
                // which we should protect against.
                Log.e(TAG, "error while granting access", ignored);
            }
            return null;
        }

        @Override
        protected void onPostExecute(Void unused) {
            finish();
        }
    }

    private static final String TAG = "KeyChain";

    private String applicationLabel;

    private final KeyStore mKeyStore = KeyStore.getInstance();

    private int mSenderUid;

    /**
     * @author see {@link Credentials}
     */
    private boolean deleteAllTypesForAlias(String alias) {
        /*
         * Make sure every type is deleted. There can be all three types, so
         * don't use a conditional here.
         */
        return this.mKeyStore.delKey(Credentials.USER_PRIVATE_KEY + alias)
                | this.mKeyStore.delete(Credentials.USER_CERTIFICATE + alias)
                | this.mKeyStore.delete(Credentials.CA_CERTIFICATE + alias);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (UserHandle.myUserId() != UserHandle.USER_OWNER) {
            showError(R.string.only_primary_user_allowed);
            resultAbort();
            return;
        }

        showGenerateDialog();
    }

    /**
     * @author Copied from {@link KeyChainActivity}
     */
    @Override
    public void onResume() {
        super.onResume();

        PendingIntent mSender = getIntent().getParcelableExtra(KeyChain.EXTRA_SENDER);
        if (mSender == null) {
            // if no sender, bail, we need to identify the app to the user
            // securely.
            resultAbort();
            return;
        }
        try {
            this.mSenderUid = getPackageManager().getPackageInfo(
                    mSender.getIntentSender().getTargetPackage(), 0).applicationInfo.uid;
        } catch (PackageManager.NameNotFoundException e) {
            // if unable to find the sender package info bail,
            // we need to identify the app to the user securely.
            resultAbort();
            return;
        }

        String pkg = mSender.getIntentSender().getTargetPackage();
        PackageManager pm = getPackageManager();
        try {
            this.applicationLabel = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0))
                    .toString();
        } catch (PackageManager.NameNotFoundException e) {
            this.applicationLabel = pkg;
        }
    }

    private void resultAbort() {
        setResult(RESULT_CANCELED);
        super.finish();
    }

    private void resultFinish(String alias) {
        setResult(RESULT_OK);

        // respond to caller with selected alias
        IKeyChainAliasCallback keyChainAliasResponse = IKeyChainAliasCallback.Stub.asInterface(
                getIntent().getIBinderExtra(KeyChain.EXTRA_RESPONSE));
        if (keyChainAliasResponse != null) {
            new ResponseSender(keyChainAliasResponse, alias).execute();
            return;
        }

        super.finish();
    }

    @SuppressWarnings("unused")
    private void showError(int errorId, int arg) {
        showError(errorId, getString(arg));
    }

    private void showError(int errorId, Object... formatArgs) {
        Toast.makeText(getApplicationContext(), getString(errorId, formatArgs),
                Toast.LENGTH_SHORT).show();
    }

    private void showGenerateDialog() {
        new GenerateDialogFragment().show(getFragmentManager(), "generatedialog");
    }
}
