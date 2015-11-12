
mifareULCPluginExport = {};

mifareULCPluginExport.init = function(successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'init', []);
}

mifareULCPluginExport.authenticate = function(key, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'authenticate', [key]);
}

mifareULCPluginExport.readPages = function(sector, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'readPages', [sector]);
}

mifareULCPluginExport.writePage = function(sector, data, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifareULCPlugin', 'writePage', [sector, data]);
}

mifareULCPluginExport.addTagDiscoveredListener = function(callback) {
	document.addEventListener("tag", callback, false);
},


module.exports = mifareULCPluginExport;