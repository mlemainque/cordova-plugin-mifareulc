
mifareULCPluginExport = {};

mifareULCPluginExport.init = function(options, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'init', [options]);
}

module.exports = mifareULCPluginExport;