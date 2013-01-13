
package com.android.keychain.manage;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ContentValues;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.os.AsyncTask;
import android.os.Bundle;
import android.provider.ContactsContract.Data;
import android.provider.ContactsContract.RawContacts;
import android.text.Editable;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.android.keychain.R;

public class ContactDetails extends Activity {
    public static final String CONTACT_ID = "contact_id";
    public static final String CONTACT_DISPLAY_NAME = "display_name";
    protected static final String TAG = "ContactDetails";

    private String mContactId;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mContactId = getIntent().getStringExtra(CONTACT_ID);

        if (mContactId == null)
            finish();

        setContentView(R.layout.contact_details);

        setTitle(getIntent().getStringExtra(CONTACT_DISPLAY_NAME));
    }

    public void addKey(View _ign) {
        Intent i = new Intent(this, KeySelectListActivity.class);
        startActivityForResult(i, 1);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == 1) {
            if (resultCode == Activity.RESULT_OK) {
                String alias = data.getStringExtra("alias");
                selectedAlias(alias);
            } else
                selectedAlias(null);
            return;
        } else {
            Log.i(TAG, "unknown request code = " + requestCode);
        }

        super.onActivityResult(requestCode, resultCode, data);
    }

    protected void selectedAlias(final String alias) {
        Log.e(TAG, "selected alias=" + alias);
        
        if (alias == null)
            return;

        AlertDialog.Builder alert = new AlertDialog.Builder(this);

        alert.setTitle(R.string.keytype_select);
        alert.setMessage(R.string.keytype_select_description);

        // Set an EditText view to get user input
        final EditText input = new EditText(this);
        alert.setView(input);

        alert.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                Editable value = input.getText();
                saveAlias(alias, value.toString());
            }
        });

        alert.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                dialog.cancel();
            }
        });

        alert.show();
    }

    protected void saveAlias(final String alias, final String type) {
        new AsyncTask<Void, Void, Boolean>() {
            private final ProgressDialog pd = new ProgressDialog(ContactDetails.this);

            @Override
            protected Boolean doInBackground(Void... params) {
                Cursor c = null;
                try {
                    c = getContentResolver().query(RawContacts.CONTENT_URI, new String[] {
                        RawContacts._ID
                    }, RawContacts.CONTACT_ID + " = ?", new String[] {
                        mContactId
                    }, null);
                    
                    if (c == null)
                        return Boolean.FALSE;
                    if (!c.moveToFirst())
                        return Boolean.FALSE;
                    
                    ContentValues values = new ContentValues();
                    values.put(Data.RAW_CONTACT_ID, c.getString(0));
                    values.put(Data.MIMETYPE, ManageContacts.MIMETYPE);
                    values.put(Data.DATA1, alias);
                    values.put(Data.DATA2, type);

                    Log.i(TAG, "inserting " + values);

                    getContentResolver().insert(Data.CONTENT_URI, values);
                    return Boolean.TRUE;
                } catch (RuntimeException e) {
                    Log.e(TAG, "error while saving alias", e);
                    return Boolean.FALSE;
                } finally {
                    if (c != null)
                        c.close();
                }
            }

            @Override
            protected void onPreExecute() {
                this.pd.setIndeterminate(true);
                this.pd.setCancelable(false);
                this.pd.show();
            }

            protected void onPostExecute(Boolean result) {
                this.pd.dismiss();
                if (!result.booleanValue()) {
                    Toast.makeText(ContactDetails.this, "Error while saving alias",
                            Toast.LENGTH_SHORT).show();
                }
            };

        }.execute();
    }
}
