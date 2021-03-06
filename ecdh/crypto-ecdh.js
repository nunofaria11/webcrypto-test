(function(global) {

  var crypto = window.crypto || window.msCrypto;
  crypto.subtle = crypto.subtle || crypto.webkitSubtle;

  if (!crypto.subtle) {
    console.warn('window.crypto API is not supported!');
    global.Crypto = null;
    return;
  }

  // Crypto type
  function Crypto(id) {
    this.id = id || (Date.now() + '');
    this.generateKeysAlgorithm = null;
    this.encryptAlgorithmIdentifier = null;
    this.privateKey = null;
    this.publicKey = null;
    this.sharedSecretKey = null;
  }

  // Properties
  Crypto.prototype.id = null;
  Crypto.prototype.generateKeysAlgorithm = null;
  Crypto.prototype.encryptAlgorithmIdentifier = null;
  Crypto.prototype.privateKey = null;
  Crypto.prototype.publicKey = null;
  Crypto.prototype.sharedSecretKey = null;


  // Init ECDH
  Crypto.prototype.init = function() {
    // Reset state
    this.generateKeysAlgorithm = null;
    this.encryptAlgorithmIdentifier = null;
    this.privateKey = null;
    this.publicKey = null;
    this.sharedSecretKey = null;

    // Set algorithms
    this.generateKeysAlgorithm = {
      name: 'ECDH',
      namedCurve: 'P-256'
    };

    this.encryptAlgorithmIdentifier = {
      name: 'AES-CBC',
      length: 256
    };

    return new Promise(
      function(resolve, reject) {
        crypto.subtle.generateKey(
          this.generateKeysAlgorithm,
          false, ['deriveKey', 'deriveBits']
        ).then(

          function(k) {

            this.privateKey = k.privateKey;
            this.publicKey = k.publicKey;

            crypto.subtle.exportKey('jwk', k.publicKey).then(
              function(jwk) {
                resolve(jwk);
              },
              function(error) {
                reject(error);
              }
            );
          }.bind(this),

          function(error) {
            reject(error)
          }
        );

      }.bind(this)
    );
  };

  Crypto.prototype.deriveSharedSecret = function(publicKeyData) {
    return new Promise(
      function(resolve, reject) {

        crypto.subtle.importKey(
          'jwk',
          publicKeyData,
          this.generateKeysAlgorithm,
          true, []
        ).then(

          function(publicKey) {

            crypto.subtle.deriveKey({
                  name: this.generateKeysAlgorithm.name,
                  namedCurve: this.generateKeysAlgorithm.namedCurve,
                  public: publicKey,
                },
                this.privateKey,
                this.encryptAlgorithmIdentifier,
                true, ["encrypt", "decrypt"]
              )
              .then(

                function(sharedSecretKey) {
                  this.sharedSecretKey = sharedSecretKey;
                  //resolve(sharedSecretKey);
                  return crypto.subtle.exportKey('jwk', sharedSecretKey).then(
                    resolve, reject
                  );

                }.bind(this),

                function(error) {
                  reject(error);
                }
              );
          }.bind(this)

        );
      }.bind(this)
    );
  };

  Crypto.prototype.encrypt = function(data) {
    return new Promise(
      function(resolve, reject) {
        if (!this.sharedSecretKey) {
          reject('No shared secret key defined.');
          return;
        }
        var iv = window.crypto.getRandomValues(new Uint8Array(16));
        crypto.subtle.encrypt({
            name: this.encryptAlgorithmIdentifier.name,
            iv: iv
          },
          // Use shared secret to encrypt
          this.sharedSecretKey,
          convertStringToArrayBufferView(data)
        ).then(
          function(result) {
            resolve({
              data: new Uint8Array(result),
              iv: iv
            });
          },
          function(error) {
            reject(error);
          }
        );
      }.bind(this));
  };

  Crypto.prototype.decrypt = function(data, iv) {
    return new Promise(function(resolve, reject) {

      crypto.subtle.decrypt({
          name: this.encryptAlgorithmIdentifier.name,
          iv: iv
        },
        // Use shared secret to decrypt
        this.sharedSecretKey,
        data
      ).then(
        function(result) {
          resolve(convertArrayBufferViewtoString(new Uint8Array(result)));
        },
        function(error) {
          reject(error);
        }
      );
    }.bind(this));
  };

  // Global export
  global.ECDHCrypto = Crypto;

  // Private scope functions
  function convertStringToArrayBufferView(str) {
    var bytes = new Uint8Array(str.length);
    for (var iii = 0; iii < str.length; iii++) {
      bytes[iii] = str.charCodeAt(iii);
    }
    return bytes;
  }

  function convertArrayBufferViewtoString(buffer) {
    var str = "";
    for (var iii = 0; iii < buffer.byteLength; iii++) {
      str += String.fromCharCode(buffer[iii]);
    }
    return str;
  }

  function _arrayBufferToJwkBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    var base64 = window.btoa(binary);
    var jwk_base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
    return jwk_base64;
  }


})(window);
