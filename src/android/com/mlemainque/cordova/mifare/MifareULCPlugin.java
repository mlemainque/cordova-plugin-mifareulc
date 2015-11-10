package com.mlemainque.cordova.mifare;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.cordova.*;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.MifareUltralight;
import android.os.Parcelable;
import android.util.Log;


public class MifareULCPlugin extends CordovaPlugin {

	private static final String INIT = "init";

	private static final String TAG_DEFAULT = "tag";

	private static final String STATUS_NFC_OK = "NFC_OK";
	private static final String STATUS_NO_NFC = "NO_NFC";
	private static final String STATUS_NFC_DISABLED = "NFC_DISABLED";

	private static final String TAG = "MifareULCPlugin";

	private final List<IntentFilter> intentFilters = new ArrayList<IntentFilter>();
	private final ArrayList<String[]> techLists = new ArrayList<String[]>();

	private PendingIntent pendingIntent = null;

	private Intent savedIntent = null;

	@Override
	public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {

		Log.d(TAG, "execute " + action);

		if (!getNfcStatus().equals(STATUS_NFC_OK)) {
			callbackContext.error(getNfcStatus());
			return true; // short circuit
		}

		createPendingIntent();

		if (action.equalsIgnoreCase(INIT)) {
			init(callbackContext);
		} else {
			return false;
		}

		return true;
	}

	private String getNfcStatus() {
		NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
		if (nfcAdapter == null) {
			return STATUS_NO_NFC;
		} else if (!nfcAdapter.isEnabled()) {
			return STATUS_NFC_DISABLED;
		} else {
			return STATUS_NFC_OK;
		}
	}

	private void init(CallbackContext callbackContext) {
		Log.d(TAG, "Enabling plugin " + getIntent());

		startNfc();
		if (!recycledIntent()) {
			parseMessage();
		}

		intentFilters.add(new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED));
		techLists.add(new String[] { MifareUltralight.class.getName() });

		callbackContext.success();
	}

	private void createPendingIntent() {
		if (pendingIntent == null) {
			Activity activity = getActivity();
			Intent intent = new Intent(activity, activity.getClass());
			intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
			pendingIntent = PendingIntent.getActivity(activity, 0, intent, 0);
		}
	}

	private void startNfc() {
		createPendingIntent(); // onResume can call startNfc before execute

		getActivity().runOnUiThread(new Runnable() {
			public void run() {
				NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

				if (nfcAdapter != null && !getActivity().isFinishing()) {
					try {
						nfcAdapter.enableForegroundDispatch(getActivity(), getPendingIntent(), getIntentFilters(), getTechLists());
						Log.d(TAG, "EnableForegroundDispatch success.");
					} catch (IllegalStateException e) {
						// issue 110 - user exits app with home button while nfc is initializing
						Log.w(TAG, "Illegal State Exception starting NFC. Assuming application is terminating.");
					}

				}
			}
		});
	}

	private void stopNfc() {
		Log.d(TAG, "stopNfc");
		getActivity().runOnUiThread(new Runnable() {
			public void run() {

				NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

				if (nfcAdapter != null) {
					try {
						nfcAdapter.disableForegroundDispatch(getActivity());
						Log.d(TAG, "DisableForegroundDispatch success.");
					} catch (IllegalStateException e) {
						// issue 125 - user exits app with back button while nfc
						Log.w(TAG, "Illegal State Exception stopping NFC. Assuming application is terminating.");
					}
				}
			}
		});
	}

	private boolean recycledIntent() { // TODO this is a kludge, find real solution
		int flags = getIntent().getFlags();
		if ((flags & Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) == Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) {
			Log.i(TAG, "Launched from history, killing recycled intent");
			setIntent(new Intent());
			return true;
		}
		return false;
	}

	private PendingIntent getPendingIntent() {
		return pendingIntent;
	}

	private IntentFilter[] getIntentFilters() {
		return intentFilters.toArray(new IntentFilter[intentFilters.size()]);
	}

	private String[][] getTechLists() {
		//noinspection ToArrayCallWithZeroLengthArrayArgument
		return techLists.toArray(new String[0][0]);
	}

	void parseMessage() {
		cordova.getThreadPool().execute(new Runnable() {
			@Override
			public void run() {
				Log.d(TAG, "parseMessage " + getIntent());
				Intent intent = getIntent();
				String action = intent.getAction();
				Log.d(TAG, "action " + action);
				if (action == null) {
					return;
				}

				Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

				if (action.equals(NfcAdapter.ACTION_TECH_DISCOVERED)) {
					for (String tagTech : tag.getTechList()) {
						Log.d(TAG, tagTech);
					}
				}
				else if (action.equals(NfcAdapter.ACTION_TAG_DISCOVERED)) {
					fireTagEvent(tag);
				}

				setIntent(new Intent());
			}
		});
	}

	private void fireTagEvent (Tag tag) {
		String command = MessageFormat.format(javaScriptEventTemplate, TAG_DEFAULT, Util.tagToJSON(tag));
		Log.v(TAG, command);
		this.webView.sendJavascript(command);
	}

	@Override
	public void onPause(boolean multitasking) {
		Log.d(TAG, "onPause " + getIntent());
		super.onPause(multitasking);
		if (multitasking) {
			// nfc can't run in background
			stopNfc();
		}
	}

	@Override
	public void onResume(boolean multitasking) {
		Log.d(TAG, "onResume " + getIntent());
		super.onResume(multitasking);
		startNfc();
	}

	@Override
	public void onNewIntent(Intent intent) {
		Log.d(TAG, "onNewIntent " + intent);
		super.onNewIntent(intent);
		setIntent(intent);
		savedIntent = intent;
		parseMessage();
	}

	private Activity getActivity() {
		return this.cordova.getActivity();
	}

	private Intent getIntent() {
		return getActivity().getIntent();
	}

	private void setIntent(Intent intent) {
		getActivity().setIntent(intent);
	}

	String javaScriptEventTemplate =
	"var e = document.createEvent(''Events'');\n" +
	"e.initEvent(''{0}'');\n" +
	"e.tag = {1};\n" +
	"document.dispatchEvent(e);";

}
