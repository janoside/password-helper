function aes_encrypt(content, password, keySize, keyDerivationIterations) {
	var salt = sjcl.random.randomWords(2);
	var key = sjcl.misc.pbkdf2(password, salt, keyDerivationIterations, keySize);
	var params = { "ks":keySize, "iter":keyDerivationIterations };
	
	var result = sjcl.encrypt(key, content, params);
	var obj = jQuery.parseJSON(result);
	obj.salt = salt;
	
	var json = JSON.stringify(obj);
	var encoded = jQuery.base64.encode(json);
	
	return encoded;
}

function aes_decrypt(content, password) {
	var decoded = jQuery.base64.decode(content);
	
	var obj = jQuery.parseJSON(decoded);
	
	var keyBits = obj["ks"];
	var keyIterations = obj["iter"];
	var salt = obj["salt"];
	
	var key = sjcl.misc.pbkdf2(password, salt, keyIterations, keyBits);
	var aes = new sjcl.cipher.aes(key);
	var ciphertext = sjcl.codec.base64.toBits(obj["ct"]);
	var iv = sjcl.codec.base64.toBits(obj["iv"]);
	
	try {
		return sjcl.codec.utf8String.fromBits(sjcl.mode.ccm.decrypt(aes, ciphertext, iv, "", obj["ts"]));
		
	} catch(e) {
		alert("cant decrypt: " + e);
		
		return false;
	}
}
