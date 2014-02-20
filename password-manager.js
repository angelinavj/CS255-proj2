"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
      priv.data.version = "CS 255 Password Manager v1.0";
      priv.data.kdf_salt = random_bitarray(256);
      priv.secrets.master_key = KDF(password, priv.data.kdf_salt);
      priv.secrets.enc_key = bitarray_slice(HMAC(priv.secrets.master_key, "0"), 0, 128);
      priv.secrets.hmac_key = HMAC(priv.secrets.master_key, "1");
      priv.secrets.salt_key = HMAC(priv.secrets.master_key, "2");
      priv.data.salt_counter = 0;
      priv.secrets.cipher = setup_cipher(priv.secrets.enc_key);
      priv.data.pwd_check = enc_gcm(priv.secrets.cipher, "0");
      priv.data.entries = {};
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    if (!bitarray_equal(trusted_data_check, SHA256(repr))) {
      throw "The data have been tampered!";
    }
    priv.data = JSON.parse(repr);

    priv.secrets.master_key = KDF(password, priv.data.kdf_salt);
    priv.secrets.enc_key = bitarray_slice(HMAC(priv.secrets.master_key, "0"), 0, 128);
    priv.secrets.hmac_key = HMAC(priv.secrets.master_key, "1");
    priv.secrets.salt_key = HMAC(priv.secrets.master_key, "2");
    priv.secrets.cipher = setup_cipher(priv.secrets.enc_key);

    return (enc_gcm(priv.secrets.cipher, "0") === priv.data.pwd_check);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    var arr = [];
    arr[0] = JSON.stringify(priv.data);
    arr[1] = SHA256(arr[0]);
    return arr;
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    keychain.init_check();
    var domain_mac = bitarray_to_base64(HMAC(priv.secrets.hmac_key, name));
    var password = priv.data.entries[domain_mac];
    if (password != undefined) {
	    var decrypted = bitarray_to_base64(lib.dec_gcm(priv.secrets.cipher, password));
	    // If no swap attacks/password matches the domain
      // TODO: do something less hacky!!
	    var domain_index = decrypted.indexOf(domain_mac.slice(0, domain_mac.length-1));
	    
	    if (domain_index != -1) {
	        var decrypted_pwd = decrypted.substring(0, domain_index);
	        return decrypted_pwd;
	    } else {
        throw "Bad keychain.get"
      }
    }
    return null;
  }

  keychain.init_check = function() {
	  if (priv.secrets.master_key == undefined) {
	    throw "Keychain not initialized!"
	  }
  }
  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
      if (priv.secrets.master_key == undefined) {
	      throw "Keychain not initialized!"
      }
      var domain_mac = HMAC(priv.secrets.hmac_key, name);
      var salt = HMAC(priv.secrets.salt_key, priv.data.salt_counter);
      priv.data.salt_counter++;

      var pwd_blob = value + bitarray_to_base64(domain_mac) + bitarray_to_base64(salt);
      var padding_len = 600 - pwd_blob.length - 1;
      var padding = "1";
      for (var i=0; i < padding_len; i++) {
	      padding += "0";
      }
      pwd_blob += padding
      
      priv.data.entries[bitarray_to_base64(domain_mac)] = (enc_gcm(priv.secrets.cipher, base64_to_bitarray(pwd_blob)));
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    keychain.init_check();
    var domain_mac = bitarray_to_base64(HMAC(priv.secrets.hmac_key, name));

    var password = priv.data.entries[domain_mac];
    if (password != undefined) {
      delete priv.data.entries[domain_mac];
      return true;
    }
    return false;
  }

  return keychain;
}

module.exports.keychain = keychain;
