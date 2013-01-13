
package com.android.keychain.manage;

import android.app.ListFragment;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.ContactsContract.Contacts;
import android.provider.ContactsContract.Data;
import android.text.TextUtils;
import android.view.View;
import android.widget.QuickContactBadge;
import android.widget.SimpleCursorAdapter;


public class KeyListFragment extends ListFragment implements LoaderCallbacks<Cursor> {

    private String contactLookupKey;
    private SimpleCursorAdapter mAdapter;

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        setEmptyText("no keys");

        this.contactLookupKey = getActivity().getIntent()
                .getStringExtra(ContactDetails.CONTACT_KEY);

        // Create an empty adapter we will use to display the loaded data.
        mAdapter = new SimpleCursorAdapter(getActivity(),
                android.R.layout.simple_list_item_2, null,
                new String[] {
                        Data.DATA1, Data.DATA2
                },
                new int[] {
                        android.R.id.text1, android.R.id.text2
                }, 0);
        mAdapter.setViewBinder(new SimpleCursorAdapter.ViewBinder() {

            @Override
            public boolean setViewValue(View view, Cursor cursor, int columnIndex) {
                if (!(view instanceof QuickContactBadge))
                    return false;

                String lk = cursor.getString(columnIndex);
                Uri uri = Uri.withAppendedPath(Contacts.CONTENT_LOOKUP_URI, lk);
                ((QuickContactBadge) view).assignContactUri(uri);

                String puri = cursor.getString(cursor.getColumnIndex(Contacts.PHOTO_THUMBNAIL_URI));
                if (!TextUtils.isEmpty(puri))
                    ((QuickContactBadge) view).setImageURI(Uri.parse(puri));
                // TODO default photo
                return true;
            }
        });
        setListAdapter(mAdapter);

        // Start out with a progress indicator.
        setListShown(false);

        // Prepare the loader. Either re-connect with an existing one,
        // or start a new one.
        getLoaderManager().initLoader(0, null, this);
    }

    @Override
    public Loader<Cursor> onCreateLoader(int arg0, Bundle arg1) {
        Uri uri = Data.CONTENT_URI;

        String select = Data.MIMETYPE + " = '" + ManageContacts.MIMETYPE + "' AND "
                + Contacts.LOOKUP_KEY + " = ?";
        return new CursorLoader(getActivity(), uri,
                new String[] {
                        Data._ID, Data.DATA1, Data.DATA2
                }, select, new String[] {
                    this.contactLookupKey
                },
                Data.DATA1 + " ASC");
    }

    @Override
    public void onLoadFinished(Loader<Cursor> arg0, Cursor data) {
        // Swap the new cursor in. (The framework will take care of closing the
        // old cursor once we return.)
        mAdapter.swapCursor(data);

        // The list should now be shown.
        if (isResumed()) {
            setListShown(true);
        } else {
            setListShownNoAnimation(true);
        }
    }

    @Override
    public void onLoaderReset(Loader<Cursor> arg0) {
        // This is called when the last Cursor provided to onLoadFinished()
        // above is about to be closed. We need to make sure we are no
        // longer using it.
        mAdapter.swapCursor(null);
    }
}
