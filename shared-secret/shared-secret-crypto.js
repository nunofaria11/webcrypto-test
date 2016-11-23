(function (global) {

  var crypto = window.crypto || window.msCrypto;
  crypto.subtle = crypto.subtle || crypto.webkitSubtle;

  if (!crypto.subtle) {
    console.warn('window.crypto API is not supported!');
    global.SharedSecretCrypto = null;
    return;
  }

  // Crypto type
  function Crypto(id) {
    this.id = id || (Date.now() + '');
    this.signatureAlgorithm = null;
    this.signaturePrivateKey = null;
    this.signaturePublicKey = null;
    this.wrapUnwrapAlgorithm = null;
    this.wrapUnwrapPrivateKey = null;
    this.wrapUnwrapPublicKey = null;
    this.externalWrapPublicKey = null;
    this.sharedSecretAlgorithm = null;
    this.sharedSecretKey = null;
    this._initAlgorithms();
  }

  // Properties
  Crypto.prototype.id = null;

  Crypto.prototype.signatureAlgorithm = null;
  Crypto.prototype.signaturePrivateKey = null;
  Crypto.prototype.signaturePublicKey = null;

  Crypto.prototype.wrapUnwrapAlgorithm = null;
  Crypto.prototype.wrapUnwrapPrivateKey = null;
  Crypto.prototype.wrapUnwrapPublicKey = null;
  Crypto.prototype.externalWrapPublicKey = null;

  Crypto.prototype.sharedSecretAlgorithm = null;
  Crypto.prototype.sharedSecretKey = null;

  // Signature methods
  Crypto.prototype.generateSignatureKeys = function () {

    return new Promise(function (resolve, reject) {
      crypto.subtle.generateKey(this.signatureAlgorithm, false, ["sign", "verify"])
        .then(
          function (key) {
            this.signaturePrivateKey = key.privateKey;
            this.signaturePublicKey = key.publicKey;
            crypto.subtle.exportKey('jwk', this.signaturePublicKey).then(
              resolve, reject
            );

          }.bind(this),
          reject
        );
    }.bind(this));
  };

  Crypto.prototype.sign = function (data) {
    return new Promise(function (resolve, reject) {
      crypto.subtle.sign(this.signatureAlgorithm, this.signaturePrivateKey, convertStringToArrayBufferView(data))
        .then(
          function (signature) {
            resolve(new Uint8Array(signature));
          },
          reject
        )
        .catch(reject);
    }.bind(this));
  };

  Crypto.prototype.importVerifyPublicKey = function (publicKeyData) {

    return new Promise(function (resolve, reject) {
      crypto.subtle.importKey('jwk', publicKeyData, this.signatureAlgorithm, false, ['verify'])
        .then(
          function (signPublicKey) {
            this.signatureVerifyPublicKey = signPublicKey;
            resolve(signPublicKey);
          }.bind(this),
          reject
        );
    }.bind(this));
  };

  Crypto.prototype.verify = function (signature, data) {
    return new Promise(
      function (resolve, reject) {
        crypto.subtle.verify(this.signatureAlgorithm, this.signatureVerifyPublicKey, signature,
          convertStringToArrayBufferView(data)
        )
          .then(
            function (valid) {
              if (valid) {
                resolve(true);
              } else {
                reject({
                  invalid: true,
                  message: 'Invalid signature!'
                });
              }
            }.bind(this),
            reject
          );
      }.bind(this)
    );
  };

  // Wrap and Unwrap methods
  Crypto.prototype.generateWrapUnwrapKeys = function () {

    return new Promise(function (resolve, reject) {
      crypto.subtle.generateKey(this.wrapUnwrapAlgorithm, false, ['wrapKey', 'unwrapKey']).then(
        function (keys) {
          this.wrapUnwrapPrivateKey = keys.privateKey;
          this.wrapUnwrapPublicKey = keys.publicKey;
          crypto.subtle.exportKey('jwk', this.wrapUnwrapPublicKey).then(
            resolve, reject
          );
        }.bind(this),
        reject
      );
    }.bind(this));
  };

  Crypto.prototype.importExternalWrapPublicKey = function (publicKeyData) {
    return new Promise(function (resolve, reject) {
      var importAlgorithm = {
        name: this.wrapUnwrapAlgorithm.name,
        hash: {
          name: this.wrapUnwrapAlgorithm.hash.name
        }
      };
      crypto.subtle.importKey('jwk', publicKeyData, importAlgorithm, true, ['wrapKey']
      ).then(
        function (publicKey) {
          this.externalWrapPublicKey = publicKey;
          resolve(publicKey);
        }.bind(this),
        function (err) {
          reject(err);
        }
      );
    }.bind(this));

  };

  Crypto.prototype.wrapPublicKey = function (key) {

    return new Promise(function (resolve, reject) {
      var wrapAlgorithm = {
        name: this.wrapUnwrapAlgorithm.name,
        hash: {
          name: this.wrapUnwrapAlgorithm.hash.name
        }
      };
      crypto.subtle.wrapKey('jwk', key, this.externalWrapPublicKey, wrapAlgorithm)
        .then(
          function (wrapped) {
            resolve(new Uint8Array(wrapped));
          }.bind(this),
          reject
        );
    }.bind(this));
  };

  Crypto.prototype.unwrapPublicKey = function (wrapped) {

    return new Promise(function (resolve, reject) {
      crypto.subtle.unwrapKey('jwk', wrapped, this.wrapUnwrapPrivateKey, this.wrapUnwrapAlgorithm, this.sharedSecretAlgorithm,
        false, ["encrypt", "decrypt"]
      ).then(
        function (key) {
          this.sharedSecretKey = key;
          resolve(key);
        }.bind(this),
        reject
      );
    }.bind(this));
  };

  // Encrypt/Decrypt methods
  Crypto.prototype.generateSharedSecretKey = function () {

    return new Promise(function (resolve, reject) {
      crypto.subtle.generateKey(this.sharedSecretAlgorithm, true, ['encrypt', 'decrypt'])
        .then(
          function (sharedSecretKey) {
            this.sharedSecretKey = sharedSecretKey;
            resolve(sharedSecretKey);
          }.bind(this),
          reject
        );
    }.bind(this));
  };

  Crypto.prototype.encrypt = function (data) {

    return new Promise(
      function (resolve, reject) {

        if (!this.sharedSecretKey) {
          reject('No external public key defined.');
          return;
        }
        var encryptAlgorithm = {
          name: this.sharedSecretAlgorithm.name,
          length: this.sharedSecretAlgorithm.length,
          iv: window.crypto.getRandomValues(new Uint8Array(16))
        };

        crypto.subtle.encrypt(encryptAlgorithm, this.sharedSecretKey, convertStringToArrayBufferView(data))
          .then(
            function (result) {
              resolve({
                data: new Uint8Array(result),
                iv: encryptAlgorithm.iv
              });
            },
            function (error) {
              reject(error);
            }
          );
      }.bind(this));
  };

  Crypto.prototype.decrypt = function (data, iv) {

    return new Promise(function (resolve, reject) {
      var decryptAlgorithm = {
        name: this.sharedSecretAlgorithm.name,
        length: this.sharedSecretAlgorithm.length,
        iv: iv
      };
      crypto.subtle.decrypt(decryptAlgorithm, this.sharedSecretKey, data)
        .then(
          function (result) {
            resolve(convertArrayBufferViewToString(new Uint8Array(result)));
          },
          function (error) {
            reject(error);
          }
        );
    }.bind(this));
  };

  // Private functions
  Crypto.prototype._initAlgorithms = function () {

    this.signatureAlgorithm = {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-256'
      }
    };

    this.wrapUnwrapAlgorithm = {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-1'
      }
    };

    this.sharedSecretAlgorithm = {
      name: 'AES-CBC',
      length: 256
    };
  };


  // Global export
  global.SharedSecretCrypto = Crypto;

  // Private scope functions
  function convertStringToArrayBufferView(str) {
    var bytes = new Uint8Array(str.length);
    for (var iii = 0; iii < str.length; iii++) {
      bytes[iii] = str.charCodeAt(iii);
    }
    return bytes;
  }

  function convertArrayBufferViewToString(buffer) {
    var str = "";
    for (var iii = 0; iii < buffer.byteLength; iii++) {
      str += String.fromCharCode(buffer[iii]);
    }
    return str;
  }

})(window);
