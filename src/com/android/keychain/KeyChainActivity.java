/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.keychain;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.Credentials;
import android.security.CryptOracle;
import android.security.IKeyChainAliasCallback;
import android.security.KeyChain;
import android.security.KeyStore;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.android.org.bouncycastle.asn1.x509.X509Name;
import com.android.org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;
@SuppressWarnings("deprecation")
public class KeyChainActivity extends Activity {
    private static final String TAG = "KeyChain";

    private static String KEY_STATE = "state";

    private static final int REQUEST_UNLOCK = 1;

    private int mSenderUid;

    private PendingIntent mSender;

    private static enum State { INITIAL, UNLOCK_REQUESTED };

    private State mState;

    // beware that some of these KeyStore operations such as saw and
    // get do file I/O in the remote keystore process and while they
    // do not cause StrictMode violations, they logically should not
    // be done on the UI thread.
    private KeyStore mKeyStore = KeyStore.getInstance();

    protected CharSequence applicationLabel;

    // the KeyStore.state operation is safe to do on the UI thread, it
    // does not do a file operation.
    private boolean isKeyStoreUnlocked() {
        return mKeyStore.state() == KeyStore.State.UNLOCKED;
    }

    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        if (savedState == null) {
            mState = State.INITIAL;
        } else {
            mState = (State) savedState.getSerializable(KEY_STATE);
            if (mState == null) {
                mState = State.INITIAL;
            }
        }
    }

    @Override public void onResume() {
        super.onResume();

        mSender = getIntent().getParcelableExtra(KeyChain.EXTRA_SENDER);
        if (mSender == null) {
            // if no sender, bail, we need to identify the app to the user securely.
            finish(null);
            return;
        }
        try {
            mSenderUid = getPackageManager().getPackageInfo(
                    mSender.getIntentSender().getTargetPackage(), 0).applicationInfo.uid;
        } catch (PackageManager.NameNotFoundException e) {
            // if unable to find the sender package info bail,
            // we need to identify the app to the user securely.
            finish(null);
            return;
        }

        // see if KeyStore has been unlocked, if not start activity to do so
        switch (mState) {
            case INITIAL:
                if (!isKeyStoreUnlocked()) {
                    mState = State.UNLOCK_REQUESTED;
                    this.startActivityForResult(new Intent(Credentials.UNLOCK_ACTION),
                                                REQUEST_UNLOCK);
                    // Note that Credentials.unlock will start an
                    // Activity and we will be paused but then resumed
                    // when the unlock Activity completes and our
                    // onActivityResult is called with REQUEST_UNLOCK
                    return;
                }
                showCertChooserDialog();
                return;
            case UNLOCK_REQUESTED:
                // we've already asked, but have not heard back, probably just rotated.
                // wait to hear back via onActivityResult
                return;
            default:
                throw new AssertionError();
        }
    }

    private void showCertChooserDialog() {
        new AliasLoader().execute();
    }

    private class AliasLoader extends AsyncTask<Void, Void, CertificateAdapter> {
        @Override protected CertificateAdapter doInBackground(Void... params) {
            String[] aliasArray = mKeyStore.saw(Credentials.USER_PRIVATE_KEY);
            List<String> aliasList = ((aliasArray == null)
                                      ? Collections.<String>emptyList()
                                      : Arrays.asList(aliasArray));
            Collections.sort(aliasList);
            return new CertificateAdapter(aliasList);
        }
        @Override protected void onPostExecute(CertificateAdapter adapter) {
            displayCertChooserDialog(adapter);
        }
    }

    private void displayCertChooserDialog(final CertificateAdapter adapter) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);

        TextView contextView = (TextView) View.inflate(this, R.layout.cert_chooser_header, null);
        View footer = View.inflate(this, R.layout.cert_chooser_footer, null);

        final ListView lv = (ListView) View.inflate(this, R.layout.cert_chooser, null);
        lv.addHeaderView(contextView, null, false);
        lv.addFooterView(footer, null, false);
        lv.setAdapter(adapter);
        builder.setView(lv);

        lv.setOnItemClickListener(new AdapterView.OnItemClickListener() {

                public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                    lv.setItemChecked(position, true);
                }
        });

        boolean empty = adapter.mAliases.isEmpty();
        int negativeLabel = empty ? android.R.string.cancel : R.string.deny_button;
        builder.setNegativeButton(negativeLabel, new DialogInterface.OnClickListener() {
            @Override public void onClick(DialogInterface dialog, int id) {
                dialog.cancel(); // will cause OnDismissListener to be called
            }
        });

        String title;
        Resources res = getResources();
        if (empty) {
            title = res.getString(R.string.title_no_certs);
        } else {
            title = res.getString(R.string.title_select_cert);
            String alias = getIntent().getStringExtra(KeyChain.EXTRA_ALIAS);
            if (alias != null) {
                // if alias was requested, set it if found
                int adapterPosition = adapter.mAliases.indexOf(alias);
                if (adapterPosition != -1) {
                    int listViewPosition = adapterPosition+1;
                    lv.setItemChecked(listViewPosition, true);
                }
            } else if (adapter.mAliases.size() == 1) {
                // if only one choice, preselect it
                int adapterPosition = 0;
                int listViewPosition = adapterPosition+1;
                lv.setItemChecked(listViewPosition, true);
            }

            builder.setPositiveButton(R.string.allow_button, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int id) {
                    int listViewPosition = lv.getCheckedItemPosition();
                    int adapterPosition = listViewPosition-1;
                    String alias = ((adapterPosition >= 0)
                                    ? adapter.getItem(adapterPosition)
                                    : null);
                    finish(alias);
                }
            });
        }
        builder.setTitle(title);
        final Dialog dialog = builder.create();


        // getTargetPackage guarantees that the returned string is
        // supplied by the system, so that an application can not
        // spoof its package.
        String pkg = mSender.getIntentSender().getTargetPackage();
        PackageManager pm = getPackageManager();
        try {
            applicationLabel = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString();
        } catch (PackageManager.NameNotFoundException e) {
            applicationLabel = pkg;
        }
        String appMessage = String.format(res.getString(R.string.requesting_application),
                                          applicationLabel);

        String contextMessage = appMessage;
        String host = getIntent().getStringExtra(KeyChain.EXTRA_HOST);
        if (host != null) {
            String hostString = host;
            int port = getIntent().getIntExtra(KeyChain.EXTRA_PORT, -1);
            if (port != -1) {
                hostString += ":" + port;
            }
            String hostMessage = String.format(res.getString(R.string.requesting_server),
                                               hostString);
            if (contextMessage == null) {
                contextMessage = hostMessage;
            } else {
                contextMessage += " " + hostMessage;
            }
        }
        contextView.setText(contextMessage);

        String installMessage = String.format(res.getString(R.string.install_new_cert_message),
                                              Credentials.EXTENSION_PFX, Credentials.EXTENSION_P12);
        TextView installText = (TextView) footer.findViewById(R.id.cert_chooser_install_message);
        installText.setText(installMessage);

        Button installButton = (Button) footer.findViewById(R.id.cert_chooser_install_button);
        installButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                // remove dialog so that we will recreate with
                // possibly new content after install returns
                dialog.dismiss();
                Credentials.getInstance().install(KeyChainActivity.this);
            }
        });

        
        boolean generateVisibility = getIntent().getBooleanExtra(CryptOracle.EXTRA_GENERATE, false);
        Log.i(TAG,  "choosePrivKey dialog (generate=" + generateVisibility + ")");
        Button generateButton = (Button) footer.findViewById(R.id.cert_chooser_generate_button);
        generateButton.setVisibility(generateVisibility ? View.VISIBLE : View.GONE);
        generateButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                // remove dialog so that we will recreate with
                // possibly new content after install returns
                dialog.dismiss();

                new GenerateDialogFragment().show(
                        KeyChainActivity.this.getFragmentManager(),
                        "generatedialog");
            }
        });

        dialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override public void onCancel(DialogInterface dialog) {
                finish(null);
            }
        });
        dialog.show();
    }

    private class CertificateAdapter extends BaseAdapter {
        private final List<String> mAliases;
        private final List<String> mSubjects = new ArrayList<String>();
        private CertificateAdapter(List<String> aliases) {
            mAliases = aliases;
            mSubjects.addAll(Collections.nCopies(aliases.size(), (String) null));
        }
        @Override public int getCount() {
            return mAliases.size();
        }
        @Override public String getItem(int adapterPosition) {
            return mAliases.get(adapterPosition);
        }
        @Override public long getItemId(int adapterPosition) {
            return adapterPosition;
        }
        @Override public View getView(final int adapterPosition, View view, ViewGroup parent) {
            ViewHolder holder;
            if (view == null) {
                LayoutInflater inflater = LayoutInflater.from(KeyChainActivity.this);
                view = inflater.inflate(R.layout.cert_item, parent, false);
                holder = new ViewHolder();
                holder.mAliasTextView = (TextView) view.findViewById(R.id.cert_item_alias);
                holder.mSubjectTextView = (TextView) view.findViewById(R.id.cert_item_subject);
                holder.mRadioButton = (RadioButton) view.findViewById(R.id.cert_item_selected);
                view.setTag(holder);
            } else {
                holder = (ViewHolder) view.getTag();
            }

            String alias = mAliases.get(adapterPosition);

            holder.mAliasTextView.setText(alias);

            String subject = mSubjects.get(adapterPosition);
            if (subject == null) {
                new CertLoader(adapterPosition, holder.mSubjectTextView).execute();
            } else {
                holder.mSubjectTextView.setText(subject);
            }

            ListView lv = (ListView)parent;
            int listViewCheckedItemPosition = lv.getCheckedItemPosition();
            int adapterCheckedItemPosition = listViewCheckedItemPosition-1;
            holder.mRadioButton.setChecked(adapterPosition == adapterCheckedItemPosition);
            return view;
        }

        private class CertLoader extends AsyncTask<Void, Void, String> {
            private final int mAdapterPosition;
            private final TextView mSubjectView;
            private CertLoader(int adapterPosition, TextView subjectView) {
                mAdapterPosition = adapterPosition;
                mSubjectView = subjectView;
            }
            @Override protected String doInBackground(Void... params) {
                String alias = mAliases.get(mAdapterPosition);
                byte[] bytes = mKeyStore.get(Credentials.USER_CERTIFICATE + alias);
                if (bytes == null) {
                    return null;
                }
                InputStream in = new ByteArrayInputStream(bytes);
                X509Certificate cert;
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    cert = (X509Certificate)cf.generateCertificate(in);
                } catch (CertificateException ignored) {
                    return null;
                }
                // bouncycastle can handle the emailAddress OID of 1.2.840.113549.1.9.1
                X500Principal subjectPrincipal = cert.getSubjectX500Principal();
                X509Name subjectName = X509Name.getInstance(subjectPrincipal.getEncoded());
                String subjectString = subjectName.toString(true, X509Name.DefaultSymbols);
                return subjectString;
            }
            @Override protected void onPostExecute(String subjectString) {
                mSubjects.set(mAdapterPosition, subjectString);
                mSubjectView.setText(subjectString);
            }
        }
    }

    private static class ViewHolder {
        TextView mAliasTextView;
        TextView mSubjectTextView;
        RadioButton mRadioButton;
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case REQUEST_UNLOCK:
                if (isKeyStoreUnlocked()) {
                    showCertChooserDialog();
                } else {
                    // user must have canceled unlock, give up
                    finish(null);
                }
                return;
            default:
                throw new AssertionError();
        }
    }

    private void finish(String alias) {
        if (alias == null) {
            setResult(RESULT_CANCELED);
        } else {
            Intent result = new Intent();
            result.putExtra(Intent.EXTRA_TEXT, alias);
            setResult(RESULT_OK, result);
        }
        IKeyChainAliasCallback keyChainAliasResponse
                = IKeyChainAliasCallback.Stub.asInterface(
                        getIntent().getIBinderExtra(KeyChain.EXTRA_RESPONSE));
        if (keyChainAliasResponse != null) {
            new ResponseSender(keyChainAliasResponse, alias).execute();
            return;
        }
        finish();
    }

    private class ResponseSender extends AsyncTask<Void, Void, Void> {
        private IKeyChainAliasCallback mKeyChainAliasResponse;
        private String mAlias;
        private ResponseSender(IKeyChainAliasCallback keyChainAliasResponse, String alias) {
            mKeyChainAliasResponse = keyChainAliasResponse;
            mAlias = alias;
        }
        @Override protected Void doInBackground(Void... unused) {
            try {
                if (mAlias != null) {
                    KeyChain.KeyChainConnection connection = KeyChain.bind(KeyChainActivity.this);
                    try {
                        connection.getService().setGrant(mSenderUid, mAlias, true);
                    } finally {
                        connection.close();
                    }
                }
                mKeyChainAliasResponse.alias(mAlias);
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
        @Override protected void onPostExecute(Void unused) {
            finish();
        }
    }

    @Override public void onBackPressed() {
        finish(null);
    }

    @Override protected void onSaveInstanceState(Bundle savedState) {
        super.onSaveInstanceState(savedState);
        if (mState != State.INITIAL) {
            savedState.putSerializable(KEY_STATE, mState);
        }
    }

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

        public GenerateDialogFragment() {
        }

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
            if (KeyChainActivity.this.mKeyStore.contains(CryptOracleService.USER_SYMKEY + alias)
                    || KeyChainActivity.this.mKeyStore.contains(Credentials.USER_CERTIFICATE
                            + alias))
                showError(R.string.alias_in_use);

            try {
                // parse key size
                keySize = Integer.parseInt(keySizeString);
            } catch (NumberFormatException e) {
                showError(R.string.invalid_key_size, e.getLocalizedMessage());
                return;
            }

            try {
                // verify key size
                KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm,
                        CryptOracleService.DEFAULT_PROVIDER);
                gen.initialize(keySize);
            } catch (GeneralSecurityException e) {
                showError(R.string.invalid_key_size, e.getLocalizedMessage());
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
            } catch (NoSuchProviderException e) {
                showError(R.string.invalid_algorithm, e.getLocalizedMessage());
                return;
            }
        }

        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container,
                Bundle savedInstanceState) {
            View v = inflater.inflate(R.layout.generate_cert_dialog, container, false);

            String appMessage = String.format(getString(R.string.requesting_application),
                    KeyChainActivity.this.applicationLabel);
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
        private final ProgressDialog pd = new ProgressDialog(KeyChainActivity.this);
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
         * @throws NoSuchProviderException 
         */
        public GenerateTask(String alias, String algorithm, int keysize, Date endDate)
                throws NoSuchAlgorithmException, NoSuchProviderException {
            this.alias = alias;
            this.endDate = endDate;
            this.subject = new X500Principal("cn=" + alias);
            this.serial = BigInteger.ONE;
            this.startDate = new Date();

            this.hashAlgorithm = MessageDigest.getInstance("MD5");
            this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                    CryptOracleService.DEFAULT_PROVIDER);
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
            
            String keyAlgo = privKey.getAlgorithm();
            String sigAlgo;
            
            if ("RSA".equals(keyAlgo))
            	sigAlgo = "sha1WithRSA";
            else if ("DSA".equals(keyAlgo))
            	sigAlgo = "sha1WithDSA";
            else if ("EC".equals(keyAlgo) || "ECDSA".equals(keyAlgo))
            	sigAlgo = "sha1WithECDSA";
            else
            	throw new IllegalArgumentException("can't handle keyAlgo="+keyAlgo);
            
            certGen.setSignatureAlgorithm(sigAlgo);

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
            return KeyChainActivity.this.mKeyStore.put(Credentials.USER_PRIVATE_KEY
                    + this.alias, privKey.getEncoded())
                    &&
                    KeyChainActivity.this.mKeyStore.put(Credentials.USER_CERTIFICATE
                            + this.alias, certBytes);
        }

        @Override
        protected void onPostExecute(Boolean result) {
            this.pd.dismiss();
            if (result == true) {
                Toast.makeText(KeyChainActivity.this,
                        getString(R.string.cert_is_added, this.alias), Toast.LENGTH_LONG).show();
                finish(this.alias);
            } else {
                Toast.makeText(KeyChainActivity.this,
                        getString(R.string.cert_not_saved, this.alias), Toast.LENGTH_LONG).show();
                finish(null);
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
}
