
package com.android.keychain.manage;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ListFragment;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.AsyncTaskLoader;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.Loader;
import android.net.Uri;
import android.os.Bundle;
import android.provider.ContactsContract.Data;
import android.security.Credentials;
import android.security.CryptOracle;
import android.security.KeyStore;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.SimpleAdapter;
import android.widget.Toast;

import com.android.keychain.CryptOracleService;
import com.android.keychain.R;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class KeysListFragment extends ListFragment implements
        LoaderCallbacks<List<Map<String, String>>> {

    private static final int FILE_SELECT_CODE = 0;
    private static final String KEY_ALIAS = "alias";
    private static final String KEY_PREFIX = "prefix";
    private static final String KEY_TYPE = "type";
    private static final String TAG = "KeyListFragment";

    private List<Map<String, String>> aliasList = new LinkedList<Map<String, String>>();

    private SimpleAdapter mAdapter;

    public KeysListFragment() {
    }

    protected void deleteKey(Map<?, ?> entry) {
        Log.e(TAG, "deleting alias " + entry);
        KeyStore ks = KeyStore.getInstance();

        String alias = (String) entry.get(KEY_ALIAS);
        String prefix = (String) entry.get(KEY_PREFIX);

        if (CryptOracleService.USER_PRIVATE_KEY.equals(prefix)) {
            ks.delete(CryptOracleService.USER_CERTIFICATE + alias);
        }

        ks.delete(prefix + alias);

        // XXX this kills assigned aliases as well

        getActivity().getContentResolver().delete(Data.CONTENT_URI,
                Data.DATA1 + "= ? AND " + Data.MIMETYPE + " = '" + ManageContacts.MIMETYPE + "'",
                new String[] {
                    alias
                });

        reloadData();
    }

    @SuppressWarnings("deprecation")
    protected void exportKey(Map<?, ?> entry) {
        Log.e(TAG, "exporting alias " + entry);

        KeyStore ks = KeyStore.getInstance();

        String alias = (String) entry.get(KEY_ALIAS);
        String prefix = (String) entry.get(KEY_PREFIX);

        if (CryptOracleService.USER_PRIVATE_KEY.equals(prefix)) {
            Toast.makeText(getActivity(), "not yet implemented",
                    Toast.LENGTH_SHORT).show();
            return;
        }

        byte[] key = ks.get(prefix + alias);

        if (key == null) {
            Toast.makeText(getActivity(), "key seems broken, deleting...",
                    Toast.LENGTH_SHORT).show();
            deleteKey(entry);
            return;
        }

        File outFile = getActivity().getFileStreamPath(alias + ".key");
        FileOutputStream out = null;
        try {
            out = getActivity().openFileOutput(alias + ".dat", Context.MODE_WORLD_READABLE);
            out.write(key);

            Intent exportIntent = new Intent(Intent.ACTION_SEND);
            exportIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            exportIntent.setType("*/*");
            exportIntent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(outFile));
            startActivity(Intent
                    .createChooser(exportIntent, getString(R.string.export_key_chooser)));
            // XXX exported keys will stay on storage
        } catch (IOException e) {
            Toast.makeText(getActivity(),
                    getActivity().getString(R.string.export_error, e.getLocalizedMessage()),
                    Toast.LENGTH_LONG).show();
        } finally {
            if (out != null)
                try {
                    out.close();
                } catch (IOException e) {
                }
        }

    }

    protected View getItemView(View baseView, final int position) {
        Object keyObjectItem = getListView().getItemAtPosition(position);
        if (!(keyObjectItem instanceof Map<?, ?>))
            return null;
        final Map<?, ?> keyMapItem = (Map<?, ?>) keyObjectItem;

        View b = baseView.findViewById(R.id.delete_button);
        b.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                deleteKey(keyMapItem);
            }
        });

        b = baseView.findViewById(R.id.export_button);
        b.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                exportKey(keyMapItem);
            }
        });

        return baseView;
    }

    protected int getListItemLayout() {
        return R.layout.manage_key_list_item;
    }

    private void importKey(Intent data) {
        if (data.hasExtra(CryptOracle.EXTRA_SYMKEY)) {
            importSymKey(data.getByteArrayExtra("symkey"));
        } else if (data.hasExtra(Credentials.EXTRA_USER_PRIVATE_KEY_NAME)
                && data.hasExtra(Credentials.EXTRA_USER_CERTIFICATE_NAME)) {
            importKeyPair(data);
        }
    }

    private void importKeyPair(Intent data) {
        KeyStore ks = KeyStore.getInstance();
        
        String privkeyName = data.getStringExtra(Credentials.EXTRA_USER_PRIVATE_KEY_NAME);
        byte[] privkey = data.getByteArrayExtra(Credentials.EXTRA_USER_PRIVATE_KEY_DATA);
        
        String certName = data.getStringExtra(Credentials.EXTRA_USER_CERTIFICATE_NAME);
        byte[] cert = data.getByteArrayExtra(Credentials.EXTRA_USER_CERTIFICATE_DATA);
        
        ks.put(CryptOracleService.PREFIX_COMMON + privkeyName, privkey);
        ks.put(CryptOracleService.PREFIX_COMMON + certName, cert);
    }

    private void importSymKey(final byte[] key) {
        final KeyStore ks = KeyStore.getInstance();
        AlertDialog.Builder alert = new AlertDialog.Builder(getActivity());

        alert.setTitle("Import key");
        alert.setMessage(R.string.credential_name);

        // Set an EditText view to get user input
        final EditText input = new EditText(getActivity());
        alert.setView(input);

        alert.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                String alias = input.getText().toString();
                ks.put(CryptOracleService.USER_SYMKEY + alias, key);
                reloadData();
            }
        });

        alert.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                dialog.dismiss();
            }
        });

        alert.show();
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        Button generateButton = (Button) getView().findViewById(R.id.cert_chooser_generate_button);
        generateButton.setVisibility(View.VISIBLE);
        generateButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new GenerateDialogFragment(getActivity(), KeysListFragment.this).show(
                        getFragmentManager(),
                        GenerateDialogFragment.TAG);
            }
        });

        Button installButton = (Button) getView().findViewById(R.id.cert_chooser_install_button);
        installButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showFileChooser();
            }
        });

        // Give some text to display if there is no data. In a real
        // application this would come from a resource.
        setEmptyText("No keys");

        setHasOptionsMenu(false);

        // Create an empty adapter we will use to display the loaded data.
        mAdapter = new SimpleAdapter(getActivity(), aliasList, getListItemLayout(),
                new String[] {
                        KEY_ALIAS, KEY_TYPE
                },
                new int[] {
                        android.R.id.text1, android.R.id.text2
                }) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                View v = super.getView(position, convertView, parent);
                return getItemView(v, position);
            }
        };

        setListAdapter(mAdapter);

        // Start out with a progress indicator.
        setListShown(false);

        getListView().setItemsCanFocus(true);

        // Prepare the loader. Either re-connect with an existing one,
        // or start a new one.
        getLoaderManager().initLoader(0, null, this);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == FILE_SELECT_CODE && resultCode == Activity.RESULT_OK) {
            importKey(data);
        }
    }

    @Override
    public Loader<List<Map<String, String>>> onCreateLoader(int id, Bundle args) {
        return new AsyncTaskLoader<List<Map<String, String>>>(getActivity()) {
            @Override
            public List<Map<String, String>> loadInBackground() {
                KeyStore ks = KeyStore.getInstance();
                String[] pAliasArray = ks.saw(CryptOracleService.USER_PRIVATE_KEY);
                String[] sAliasArray = ks.saw(CryptOracleService.USER_SYMKEY);

                if (pAliasArray == null)
                    pAliasArray = new String[] {};
                if (sAliasArray == null)
                    sAliasArray = new String[] {};

                List<Map<String, String>> list = new ArrayList<Map<String, String>>(
                        pAliasArray.length + sAliasArray.length);

                for (String alias : pAliasArray) {
                    Map<String, String> map = new HashMap<String, String>(2);
                    map.put(KEY_ALIAS, alias);
                    map.put(KEY_PREFIX, CryptOracleService.USER_PRIVATE_KEY);
                    map.put(KEY_TYPE, getContext().getString(R.string.private_key));

                    list.add(map);
                }

                for (String alias : sAliasArray) {
                    Map<String, String> map = new HashMap<String, String>(2);
                    map.put(KEY_ALIAS, alias);
                    map.put(KEY_PREFIX, CryptOracleService.USER_SYMKEY);
                    byte[] key = ks.get(CryptOracleService.USER_SYMKEY + alias);
                    int bits = 0;
                    if (key != null)
                        bits = key.length * 8;
                    map.put(KEY_TYPE, getContext().getString(R.string.secret_key, bits));

                    list.add(map);
                }
                Log.e(TAG, "got new data=" + list);
                return list;
            }

            @Override
            protected void onStartLoading() {
                forceLoad();
            }
        };
    }

    @Override
    public View onCreateView(android.view.LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState) {
        return inflater.inflate(R.layout.keys_list_fragment, null);
    }

    @Override
    public void onLoaderReset(Loader<List<Map<String, String>>> loader) {
        mAdapter.notifyDataSetInvalidated();
        aliasList.clear();
    }

    @Override
    public void onLoadFinished(Loader<List<Map<String, String>>> loader,
            List<Map<String, String>> data) {
        aliasList.clear();
        aliasList.addAll(data);
        mAdapter.notifyDataSetChanged();

        Log.e(TAG, "aliasList set to=" + aliasList);

        if (isResumed()) {
            setListShown(true);
        } else {
            setListShownNoAnimation(true);
        }
    }

    public void reloadData() {
        getLoaderManager().restartLoader(0, null, this);
        Log.e(TAG, "reloadData");
    }

    private void showFileChooser() {

        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setClassName("com.android.certinstaller", "com.android.certinstaller.KeyFileList");

        try {
            startActivityForResult(intent, FILE_SELECT_CODE);
        } catch (android.content.ActivityNotFoundException ex) {
            Toast.makeText(getActivity(), "Please install a File Manager.",
                    Toast.LENGTH_SHORT).show();
        }
    }
}
