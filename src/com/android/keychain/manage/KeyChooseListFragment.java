
package com.android.keychain.manage;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Checkable;
import android.widget.ListView;
import com.android.keychain.R;

import java.util.Map;

public class KeyChooseListFragment extends KeysListFragment {
    @Override
    protected int getListItemLayout() {
        return R.layout.simple_list_item_2_single_choice;
    }
    
    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        getListView().setChoiceMode(ListView.CHOICE_MODE_SINGLE);
        getListView().setItemsCanFocus(false);
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

    @Override
    public void onListItemClick(ListView l, View v, int position, long id) {
        l.setItemChecked(position, true);
    }
    
    @Override
    protected View getItemView(View baseView, int position) {
        Checkable c = (Checkable) baseView.findViewById(R.id.radio);
        if (c == null)
            throw new IllegalArgumentException("didn't find checkbox in item view " + baseView);
        c.setChecked(getListView().isItemChecked(position));
        return baseView;
    }
}
