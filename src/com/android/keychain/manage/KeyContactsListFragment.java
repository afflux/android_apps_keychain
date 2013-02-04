
package com.android.keychain.manage;

import android.app.ListFragment;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.ContentUris;
import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.ContactsContract.Contacts;
import android.provider.ContactsContract.Data;
import android.security.CryptOracle;
import android.view.View;
import android.widget.QuickContactBadge;
import android.widget.SimpleCursorAdapter;
import com.android.keychain.R;

public class KeyContactsListFragment extends ListFragment
        implements LoaderCallbacks<Cursor> {

    // This is the Adapter being used to display the list's data.
    SimpleCursorAdapter mAdapter;
    String alias;

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        alias = getActivity().getIntent().getStringExtra(CryptOracle.EXTRA_ALIAS);

        // Give some text to display if there is no data. In a real
        // application this would come from a resource.
        setEmptyText("No contacts assigned");

        // Create an empty adapter we will use to display the loaded data.
        mAdapter = new SimpleCursorAdapter(getActivity(),
                R.layout.contact_row, null,
                new String[] {
                        Data.DISPLAY_NAME, Data.LOOKUP_KEY
                },
                new int[] {
                        R.id.name, R.id.picture
                }, 0);
        mAdapter.setViewBinder(new SimpleCursorAdapter.ViewBinder() {

            @Override
            public boolean setViewValue(View view, Cursor cursor, int columnIndex) {
                if (!(view instanceof QuickContactBadge))
                    return false;

                String lk = cursor.getString(columnIndex);

                Uri uri = Uri.withAppendedPath(Contacts.CONTENT_LOOKUP_URI, lk);
                ((QuickContactBadge) view).assignContactUri(uri);

                long photoId = cursor.getLong(cursor.getColumnIndex(Data.PHOTO_ID));
                uri = ContentUris.withAppendedId(Data.CONTENT_URI, photoId);

                if (photoId > -1 && !Build.FINGERPRINT.contains("generic"))
                    ((QuickContactBadge) view).setImageURI(uri);
                else
                    ((QuickContactBadge) view).setImageResource(R.drawable.ic_contact_picture);
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

    // These are the Contacts rows that we will retrieve.
    static final String[] CONTACTS_SUMMARY_PROJECTION = new String[] {
            Data._ID,
            Data.DISPLAY_NAME,
            Data.PHOTO_ID,
            Data.LOOKUP_KEY,
    };

    public Loader<Cursor> onCreateLoader(int id, Bundle args) {
        // This is called when a new Loader needs to be created. This
        // sample only has one Loader, so we don't care about the ID.
        // First, pick the base URI to use depending on whether we are
        // currently filtering.
        Uri baseUri = Data.CONTENT_URI;

        // Now create and return a CursorLoader that will take care of
        // creating a Cursor for the data being displayed.
        String select = "((" + Data.DISPLAY_NAME + " NOTNULL) AND ("
                + Data.DISPLAY_NAME + " != '' ) AND ("
                + Data.DATA1 + "= ? ))";
        return new CursorLoader(getActivity(), baseUri,
                CONTACTS_SUMMARY_PROJECTION, select, new String[] {
                    alias
                },
                Data.DISPLAY_NAME + " COLLATE LOCALIZED ASC");
    }

    public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
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

    public void onLoaderReset(Loader<Cursor> loader) {
        // This is called when the last Cursor provided to onLoadFinished()
        // above is about to be closed. We need to make sure we are no
        // longer using it.
        mAdapter.swapCursor(null);
    }
}
