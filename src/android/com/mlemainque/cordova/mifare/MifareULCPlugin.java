package com.mlemainque.cordova.mifare;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.security.SecureRandom;

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

	private void readUltralightTag() {
		if (getIntent() == null) {  // TODO remove this and handle LostTag
			Log.w(TAG, "Failed to write tag, received null intent");
			//callbackContext.error("Failed to write tag, received null intent");
		}

		final Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

		cordova.getThreadPool().execute(new Runnable() {
			@Override
			public void run() {
				try {
					MifareUltralight ulTag = MifareUltralight.get(tag);
					if (ulTag != null) {
						ulTag.connect();

						if (true || ulTag.getType() == MifareUltralight.TYPE_ULTRALIGHT_C) {

							Log.d(TAG, "Ultralight C authenticating ...");

							ulTag.setTimeout(100);

							//byte[] key = new byte[16];
							//byte[] key = Util.hexStringToByteArray("49454D4B41455242214E4143554F5945"); // FAIL
							byte[] key = Util.hexStringToByteArray("49454D4B41455242214E4143554F5946"); // SUCCESS

							/*
							byte[] rB = Util.hexStringToByteArray("51E764602678DF2B");
							byte[] ekrB = Util.TripleDES_encrypt(key, iv, rB);
							iv = new byte[8];
							byte[] rB2 = Util.TripleDES_decrypt(key, iv, ekrB);
							iv = new byte[8];
							Log.d(TAG, "ekrB = "+Util.bytesToHex(ekrB));
							Log.d(TAG, "rB2 = "+Util.bytesToHex(rB2));
							*/
							
							byte[] ek_rndB = ulTag.transceive(new byte[]{26, 0});
							ek_rndB = Arrays.copyOfRange(ek_rndB, 1, 9);
							Log.d(TAG, "ek_RndB = "+Util.bytesToHex(ek_rndB));

							SecureRandom sr = new SecureRandom();
							byte[] rndA = new byte[8];
							sr.nextBytes(rndA);
							Log.d(TAG, "rndA = "+Util.bytesToHex(rndA));

							/*
							byte[] iv2 = new byte[8];
							byte[] ek_rndA = Util.TripleDES_encrypt(key, iv2, rndA);
							Log.d(TAG, "ek_rndA = "+Util.bytesToHex(ek_rndA));
							iv2 = new byte[8];
							byte[] rndA2 = Util.TripleDES_decrypt(key, iv2, rndA);
							Log.d(TAG, "rndA2 = "+Util.bytesToHex(rndA2));
							*/

							byte[] iv = new byte[8];

							byte[] rndB = Util.TripleDES_decrypt(key, iv, ek_rndB);
							Log.d(TAG, "rndB = "+Util.bytesToHex(rndB));

							System.arraycopy(ek_rndB, ek_rndB.length-8, iv, 0, 8);

							byte[] rndBshift = new byte[] { rndB[1], rndB[2], rndB[3], rndB[4], rndB[5], rndB[6], rndB[7], rndB[0] };
							Log.d(TAG, "rndBshift = "+Util.bytesToHex(rndBshift));
							
							byte[] rndA_rndBshift = new byte[16];
							System.arraycopy(rndA, 0, rndA_rndBshift, 0, 8);
							System.arraycopy(rndBshift, 0, rndA_rndBshift, 8, 8);
							Log.d(TAG, "rndA_rndBshift = "+Util.bytesToHex(rndA_rndBshift));

							byte[] iv2 = iv.clone();
							byte[] ek_rndA_rndBshift = Util.TripleDES_encrypt(key, iv, rndA_rndBshift);
							iv = iv2;
							Log.d(TAG, "ek_rndA_rndBshift = "+Util.bytesToHex(ek_rndA_rndBshift));

							System.arraycopy(ek_rndA_rndBshift, ek_rndA_rndBshift.length-8, iv, 0, 8);

							byte[] message = new byte[17];
							message[0] = -81;
							System.arraycopy(ek_rndA_rndBshift, 0, message, 1, 16);
							Log.d(TAG, "message = "+Util.bytesToHex(message));

							byte[] ek_rndAshift = ulTag.transceive(message);
							ek_rndAshift = Arrays.copyOfRange(ek_rndAshift, 1, 9);
							Log.d(TAG, "ek_rndAshift = "+Util.bytesToHex(ek_rndAshift));

							byte[] rndAshift_1 = Util.TripleDES_decrypt(key, iv, ek_rndAshift);
							byte[] rndAshift_2 = new byte[] { rndA[1], rndA[2], rndA[3], rndA[4], rndA[5], rndA[6], rndA[7], rndA[0] };
							Log.d(TAG, "rndAshift_1 = "+Util.bytesToHex(rndAshift_1));
							Log.d(TAG, "rndAshift_2 = "+Util.bytesToHex(rndAshift_2));
						} else {
							Log.w(TAG, "Tag isn't an Ultralight C but "+ulTag.getType());
							//callbackContext.error("Tag isn't an Ultralight C");
						}
					} else {
						Log.w(TAG, "Tag isn't an Ultralight");
						//callbackContext.error("Tag isn't an Ultralight");
					}
				} catch (TagLostException e) {
					//callbackContext.error(e.getMessage());
					Log.w(TAG, e.getMessage());
				} catch (IOException e) {
					//callbackContext.error(e.getMessage());
					Log.w(TAG, e.getMessage());
				} catch (Exception e) {
					Log.w(TAG, e.getMessage());
				}
			}
		});
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
					readUltralightTag();
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
