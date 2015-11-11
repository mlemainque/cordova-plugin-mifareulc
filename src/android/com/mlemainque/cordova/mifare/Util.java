package com.mlemainque.cordova.mifare;


import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.Tag;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Util {

	static final String TAG = "MifareULCPlugin";

	static JSONObject tagToJSON(Tag tag) {
		JSONObject json = new JSONObject();

		if (tag != null) {
			try {
				json.put("id", byteArrayToJSON(tag.getId()));
				json.put("techTypes", new JSONArray(Arrays.asList(tag.getTechList())));
			} catch (JSONException e) {
				Log.e(TAG, "Failed to convert tag into json: " + tag.toString(), e);
			}
		}
		return json;
	}

	static JSONArray byteArrayToJSON(byte[] bytes) {
		JSONArray json = new JSONArray();
		for (byte aByte : bytes) {
			json.put(aByte);
		}
		return json;
	}

	static byte[] jsonToByteArray(JSONArray json) throws JSONException {
		byte[] b = new byte[json.length()];
		for (int i = 0; i < json.length(); i++) {
			b[i] = (byte) json.getInt(i);
		}
		return b;
	}

	private static byte[] TripleDES_engine(byte[] password_16, byte[] iv_array, byte[] message, int mode) throws Exception {
		// On génère la clé de 24 octets à partir de celle de 16
		// (2-Key 3DES)
		final byte[] password_24 = Arrays.copyOf(password_16, 24);
		for (int j = 0, k = 16; j < 8;) {
			password_24[k++] = password_16[j++];
		}
		final SecretKey key = new SecretKeySpec(password_24, "DESede");

		// On initialise le vecteur IV
		final IvParameterSpec iv = new IvParameterSpec(iv_array);
		//Log.d(TAG, "IV = "+Util.bytesToHex(iv_array));

		// On réalise l'opération
		final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
		cipher.init(mode, key, iv);
		final byte[] result = cipher.doFinal(message);

		// On renvoie le résultat et on modifie la valeur de IV
		System.arraycopy(message, message.length-8, iv_array, 0, 8);
		return result;
	}

	static byte[] TripleDES_encrypt(byte[] password, byte[] iv, byte[] message) throws Exception {
		return TripleDES_engine(password, iv, message, Cipher.ENCRYPT_MODE);
	}

	static byte[] TripleDES_decrypt(byte[] password, byte[] iv, byte[] message) throws Exception {
		return TripleDES_engine(password, iv, message, Cipher.DECRYPT_MODE);
	}

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 3];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 3] = hexArray[v >>> 4];
			hexChars[j * 3 + 1] = hexArray[v & 0x0F];
			hexChars[j * 3 + 2] = ' ';
		}
		return new String(hexChars);
	}

	static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
				+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

}
