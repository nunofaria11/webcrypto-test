(function(global) {

  var crypto = window.crypto || window.msCrypto;
  crypto.subtle = crypto.subtle || crypto.webkitSubtle;

  if (!crypto.subtle) {
    console.warn('window.crypto API is not supported!');
    global.Crypto = null;
    return;
  }

  // Crypto type
  function Crypto() {
    this.algorithmIdentifier = null;
    this.privateKey = null;
    this.publicKey = null;
    this.externalPublicKey = null;
  }

  // Properties
  Crypto.prototype.algorithmIdentifier = null;
  Crypto.prototype.privateKey = null;
  Crypto.prototype.publicKey = null;
  Crypto.prototype.externalPublicKey = null;

  Crypto.prototype.init = function(algorithm, hash) {
    // Reset state
    this.algorithmIdentifier = null;
    this.privateKey = null;
    this.publicKey = null;
    this.externalPublicKey = null;

    // Set algorithm and hash
    this._setAlgorithm(algorithm, hash);

    return new Promise(
      function(resolve, reject) {
        var asymmetricEncAlgorithm, keyPromise;

        if (!this.algorithmIdentifier || !this.algorithmIdentifier.name) {
          reject('No algorithm defined.');
          return;
        }

        asymmetricEncAlgorithm = {
          name: this.algorithmIdentifier.name,
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: {
            name: this.algorithmIdentifier.hash.name // SHA-1, SHA-256
          }
        };

        keyPromise = crypto.subtle.generateKey(asymmetricEncAlgorithm, false, ['encrypt', 'decrypt']);
        keyPromise.then(
          function(k) {
            this.privateKey = k.privateKey;
            this.publicKey = k.publicKey;

            crypto.subtle.exportKey('jwk', k.publicKey).then(
              function(jwk) {
                resolve(jwk);
              },
              function(error) {
                reject(error);
              });

          }.bind(this),
          function(error) {
            reject(error)
          }
        );

      }.bind(this)
    );
  };

  Crypto.prototype.setExternalPublicKey = function(publicKey) {
    return new Promise(function(resolve, reject) {
      crypto.subtle.importKey(
        'jwk',
        publicKey, {
          name: this.algorithmIdentifier.name,
          hash: {
            name: this.algorithmIdentifier.hash.name
          }
        },
        false, ['encrypt']
      ).then(
        function(pk) {
          this.externalPublicKey = pk;
          resolve(pk);
        }.bind(this),
        function(err) {
          reject(err);
        });
    }.bind(this));

  }

  Crypto.prototype.encrypt = function(data) {
    return new Promise(
      function(resolve, reject) {
        if (!this.externalPublicKey) {
          reject('No external public key defined.');
          return;
        }
        crypto.subtle.encrypt(
          this.algorithmIdentifier,
          this.externalPublicKey,
          convertStringToArrayBufferView(data)
        ).then(
          function(result) {
            resolve(new Uint8Array(result));
          },
          function(error) {
            reject(error);
          }
        );
      }.bind(this));
  };

  Crypto.prototype.decrypt = function(data) {
    return new Promise(function(resolve, reject) {
      crypto.subtle.decrypt(
        this.algorithmIdentifier,
        this.privateKey,
        data
      ).then(
        function(result) {
          resolve(convertArrayBufferViewtoString(new Uint8Array(result)));
        },
        function(error) {
          reject(error);
        });
    }.bind(this));
  };

  // Private functions
  Crypto.prototype._setAlgorithm = function(algorithm, hash) {
    if (algorithm && hash) {
      this.algorithmIdentifier = {
        name: algorithm, // Algorithm name
        hash: {
          name: hash // http://stackoverflow.com/a/33176125/691916
        },
        // iv: Is initialization vector. It must be 16 bytes
        iv: crypto.getRandomValues(new Uint8Array(16))
      };
    }
  };

  // Global export
  global.Crypto = Crypto;

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
