
package com.android.keychain.manage;

import android.app.ListFragment;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.AsyncTaskLoader;
import android.content.Loader;
import android.os.Bundle;
import android.security.KeyStore;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Checkable;
import android.widget.ListView;
import android.widget.SimpleAdapter;
import com.android.keychain.CryptOracleService;
import com.android.keychain.R;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class KeySelectListFragment extends ListFragment implements
        LoaderCallbacks<List<Map<String, String>>> {

    private List<Map<String, String>> aliasList = new LinkedList<Map<String, String>>();
    private SimpleAdapter mAdapter;

    public KeySelectListFragment() {
    }
    
    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        
        // Give some text to display if there is no data. In a real
        // application this would come from a resource.
        setEmptyText("No keys");

        // We have a menu item to show in action bar.
        setHasOptionsMenu(false);
        
        getListView().setChoiceMode(ListView.CHOICE_MODE_SINGLE);

        // Create an empty adapter we will use to display the loaded data.
        mAdapter = new SimpleAdapter(getActivity(), aliasList,
                R.layout.simple_list_item_2_single_choice,
                new String[] {
                        "alias", "type"
                },
                new int[] {
                        android.R.id.text1, android.R.id.text2
                }) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                View v = super.getView(position, convertView, parent);
                Checkable c = (Checkable) v.findViewById(R.id.radio);
                c.setChecked(getListView().isItemChecked(position));
                return v;
            }
        };
        
        setListAdapter(mAdapter);

        // Start out with a progress indicator.
        setListShown(false);

        // Prepare the loader. Either re-connect with an existing one,
        // or start a new one.
        getLoaderManager().initLoader(0, null, this);
    }
    
    public void reloadData() {
        getLoaderManager().restartLoader(0, null, this);
        Log.e("KeySelectListFragment", "reloadData");
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
                    map.put("alias", alias);
                    map.put("type", getContext().getString(R.string.private_key));

                    list.add(map);
                }

                for (String alias : sAliasArray) {
                    Map<String, String> map = new HashMap<String, String>(2);
                    map.put("alias", alias);
                    map.put("type", getContext().getString(R.string.secret_key));

                    list.add(map);
                }
                Log.e("Blerg", "got new data=" + list);
                return list;
            }
            
            @Override
            protected void onStartLoading() {
                forceLoad();
            }
        };
    }

    @Override
    public void onLoadFinished(Loader<List<Map<String, String>>> loader,
            List<Map<String, String>> data) {
        aliasList.clear();
        aliasList.addAll(data);
        mAdapter.notifyDataSetChanged();
        
        Log.e("Blerg", "aliasList set to=" + aliasList);
        
        if (isResumed()) {
            setListShown(true);
        } else {
            setListShownNoAnimation(true);
        }
    }

    @Override
    public void onLoaderReset(Loader<List<Map<String, String>>> loader) {
        mAdapter.notifyDataSetInvalidated();
        aliasList.clear();
    }
    
    @Override
    public void onListItemClick(ListView l, View v, int position, long id) {
        l.setItemChecked(position, true);
    }
    
    public String getSelectedAlias() {
        int position = getListView().getCheckedItemPosition();
        Log.e("Blerg", "currently checked index=" + position);
        Object selected = getListView().getItemAtPosition(position);
        Log.e("Blerg", "currently selected=" + selected);
        if (!(selected instanceof Map<?, ?>))
            return null;
        Map<?, ?> selectedItem = (Map<?, ?>) selected;
        return (String) selectedItem.get("alias");
    }
}
