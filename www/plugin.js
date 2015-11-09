
mifareULCexport = {};

mifareULCexport.init = function(options, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifarePlugin', 'init', [options]);
}

module.exports = mifareULCexport;