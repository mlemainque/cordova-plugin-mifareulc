
mifareULCPlugin = {};

/**
 * Starts the Mifare Ultralight C plugin
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.init = function(successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'init', []);
}

/**
 * Performs authentication
 * @param  {Int[]}			key 			Must be a 16-byte array
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.authenticate = function(key, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'authenticate', [key]);
}

/**
 * Read four pages
 * @param  {Integer}		page     	    First read page
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.readPages = function(page, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'readPages', [page]);
}

/**
 * Write one data page
 * @param  {Integer}		page			A data-page number (within 4 and 40)
 * @param  {Int[]}			data 			Must be a 4-byte array
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.writePage = function(page, data, successCallback, failureCallback) {
	if (page < 4 || page > 41) {
		failureCallback("This isn't a data page");
		return;
	}
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [page, data]);
}

/**
 * Read OTP page
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.readOTP = function(successCallback, failureCallback) {
    mifareULCPlugin.readPages(3, function(e) {
        successCallback(e.data.slice(0, 4).join().toString(2));
    });
}

/**
 * Set OTP bit
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.setOTP = function(data, successCallback, failureCallback) {
    var splitted_data = [];
    for (var i = 0 ; i < 4 ; i++) {
        splitted_data.push(parseInt(data.slice(j*8, (j+1)*8), 2));
    }
    console.log(splitted_data);
	//cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [3, splitted_data]);
}

/**
 * Set AUTH0 parameter eg. the page number from which authentication will be required
 * @param  {Integer}		page			Page number from which authentication will be required (from 0 to 48)
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.writeAuth0 = function(page, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [42, [page, 0, 0, 0]]);
}

/**
 * Set AUTH1 parameter eg. if authentication is required or not to read protected pages
 * @param  {Boolean}		readAllowed
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.writeAuth1 = function(readAllowed, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [43, [readAllowed?1:0, 0, 0, 0]]);
}

/**
 * Set the authentication key
 * @param  Array<Int>		key				16-byte array
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.writeKey = function(key, successCallback, failureCallback) {
	if (key.length != 16) {
		failureCallback("Key must be a 16-bytes array");
		return;
	}
	key2 = key.slice(0);
	key2.reverse();
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [44, key2.slice(8, 12)]);
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [45, key2.slice(12, 16)]);
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [46, key2.slice(0, 4)]);
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [47, key2.slice(4, 8)]);
}

/**
 * Add a listener on "tag discovered" event
 * @param {Function} callback
 */
mifareULCPlugin.addTagDiscoveredListener = function(callback) {
	document.addEventListener("tag", callback, false);
}

/**
 * Remove a listener from "tag discovered" event
 * @param {Function} callback
 */
mifareULCPlugin.removeTagDiscoveredListener = function(callback) {
	document.removeEventListener("tag", callback);
}

/**
 * Dump every available data from the C tag
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.dumpUltralightC = function(successCallback, failureCallback) {
	for (var i = 0 ; i < 48 ; i += 4) {
		mifareULCPlugin.readPages(i, function(e) {
			for (j = 0 ; j < 4 ; j++) {
				successCallback({
					sector: e.sector+j,
					data: e.data.slice(j*4, (j+1)*4)
				});
			}
		},
		failureCallback);
	}
}

/**
 * Dump every available data from the tag
 * @param  {Function}		successCallback
 * @param  {Function}		failureCallback
 * @return nothing
 */
mifareULCPlugin.dumpUltralight = function(successCallback, failureCallback) {
	for (var i = 0 ; i < 16 ; i += 4) {
		mifareULCPlugin.readPages(i, function(e) {
			for (j = 0 ; j < 4 ; j++) {
				successCallback({
					sector: e.sector+j,
					data: e.data.slice(j*4, (j+1)*4)
				});
			}
		},
		failureCallback);
	}
}


module.exports = mifareULCPlugin;