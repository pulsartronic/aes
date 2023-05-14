let AES = {};

AES.GCM = function(key) {
	this.keyBuffer = key;
	this.encoder = new TextEncoder("UTF-8");
	this.decoder = new TextDecoder("UTF-8");
};

AES.GCM.prototype.initKey = async function() {
	if (!this.key) {
		let options = {"name":"AES-GCM"};
		this.key = await globalThis.crypto.subtle.importKey("raw", this.keyBuffer, options, false, ["encrypt", "decrypt"]);
	}
};

AES.GCM.prototype.encrypt = async function(dataBuffer) {
	await this.initKey();
	let iv = new Uint8Array(12);
	globalThis.crypto.getRandomValues(iv);
	let options = {"name":"AES-GCM","iv":iv,"tagLength":128};
	let encryptedBuffer = await globalThis.crypto.subtle.encrypt(options, this.key, dataBuffer);
	let ebuffer = new Uint8Array(encryptedBuffer);
	var edata = new Uint8Array(iv.length + ebuffer.length);
	edata.set(iv);
	edata.set(ebuffer, iv.length);
	return edata.buffer;
};

AES.GCM.prototype.decrypt = async function(dataBuffer) {
	await this.initKey();
	var iv = new Uint8Array(dataBuffer, 0, 12);
	let ebuffer = new Uint8Array(dataBuffer, 12);
	let options = {"name":"AES-GCM","iv":iv,"tagLength":128};
	let ddata = await globalThis.crypto.subtle.decrypt(options, this.key, ebuffer);
	return ddata;
};

export default AES;
