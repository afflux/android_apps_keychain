
package com.android.keychain.manage;

import android.app.ListFragment;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.os.Bundle;
import android.provider.ContactsContract.Data;
import android.view.View;
import android.widget.ListView;
import android.widget.SimpleCursorAdapter;
import android.widget.Toast;

public class KeyListFragment extends ListFragment implements LoaderCallbacks<Cursor> {

    private String contactLookupId;
    private SimpleCursorAdapter mAdapter;

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        setEmptyText("no keys");

        this.contactLookupId = getActivity().getIntent()
                .getStringExtra(ContactDetails.CONTACT_ID);

        // Create an empty adapter we will use to display the loaded data.
        mAdapter = new SimpleCursorAdapter(getActivity(),
                android.R.layout.simple_list_item_2, null,
                new String[] {
                        Data.DATA1, Data.DATA2
                },
                new int[] {
                        android.R.id.text1, android.R.id.text2
                }, 0);

        setListAdapter(mAdapter);

        // Start out with a progress indicator.
        setListShown(false);

        // Prepare the loader. Either re-connect with an existing one,
        // or start a new one.
        getLoaderManager().initLoader(0, null, this);
    }

    @Override
    public Loader<Cursor> onCreateLoader(int arg0, Bundle arg1) {

        String select = Data.MIMETYPE + " = '" + ManageContacts.MIMETYPE + "' AND "
                + Data.CONTACT_ID + " = ?";
        return new CursorLoader(getActivity(), Data.CONTENT_URI,
                new String[] {
                        Data._ID, Data.DATA1, Data.DATA2
                }, select, new String[] {
                        this.contactLookupId
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

    @Override
    public void onListItemClick(ListView l, View v, int position, long id) {
        // TODO
        Toast.makeText(getActivity(), "not yet implemented", Toast.LENGTH_SHORT).show();
    }
}
