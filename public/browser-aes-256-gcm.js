// aes4js, by Samuel Olugbemi. MIT applies.
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof exports === 'object') {
    module.exports = factory();
  } else {
    root.aes4js = factory();
  }
}(this, function () {

  function aesEnc(password, salt, tagLength, algorithm, iterations, str) {
    var iv = window.crypto.getRandomValues(new Uint8Array(12)),
      encoder = new TextEncoder('utf-8'),
      encodedString = encoder.encode(str),
      bin = false;
    if (typeof str === "object") { // allows binary as well as string input
      encodedString = str; // arrayish
      bin = true;
    }

    return derive(password, salt, algorithm, iterations).then(function (key) {
        return window.crypto.subtle.encrypt({
            name: algorithm,
            iv: iv,
            tagLength: tagLength,
          }, key, encodedString)
          .then(function (encrypted) {
            return new Promise(function (resolve, reject) {
              const tagIdx = encrypted.byteLength - ((tagLength + 7) >> 3);
              let ciphertext = encrypted.slice(0, tagIdx);
              let tag = encrypted.slice(tagIdx);
              const cipher = [
                _arrayBufferToBase64(ciphertext),
                _arrayBufferToBase64(iv),
                _arrayBufferToBase64(tag)
              ].join('--')
              resolve(cipher);
            }); // end fr promise wrapper
          }); //end encrypt
      }) //end derive
      .catch(console.error);
  } /* end aesEnc() */

  function _arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function aesDec(password, salt, tagLength, algorithm, iterations, obj) {
    if (typeof obj === "string") obj = JSON.parse(obj);
    return derive(password, salt, algorithm, iterations).then(function (key) {
      return new Promise(function (resolve, reject) { // turn dataURL into bin array:
          var [bundle, ivArr] = dataUrlToBlob(obj.encrypted);
          window.crypto.subtle.decrypt({
              name: algorithm,
              iv: ivArr,
              tagLength: tagLength,
            }, key, bundle)
            .then(function (decryptedBin) { // if not bin input, decode:
              return obj.bin ? decryptedBin : uintToString(decryptedBin, obj.json);
            })
            .then(resolve)
            .catch(function (y) { // given a op err here, a wrong pw was given
              if (String(y) === "OperationError") y = "Opps!\r\n\r\nWrong Password, try again.";
              reject(y);
              //resolve(y);
            }); //end catch
        }) //end promise wrapper
        .catch(function (e) {
          throw e;
        });
    }); //end derive
  } /* end aesDec() */

  function uintToString(uintArray, json) {
    var encodedString = new TextDecoder('utf-8').decode(uintArray)
    if (json && !isJson(encodedString)) {
      uintArray = uintArray.slice(7, -5)
      encodedString = new TextDecoder('utf-8').decode(uintArray)
      if (!isJson(encodedString)) {
        throw 'Decoded cipherText is not a JSON object!';
      }
    }
    decodedString = decodeURIComponent(escape(encodedString));
    return decodedString;
  }

  function isJson(str) {
    try {
      JSON.parse(str);
    } catch (e) {
      return false;
    }
    return true;
  }

  // function sha256(str) {
  //   return crypto.subtle.digest("SHA-1", new TextEncoder("utf-8").encode(str))
  //     .then(function (x) { // turn into hex string:
  //       return Array.from(new Uint8Array(x)).map(function (b) {
  //         return ('00' + b.toString(16)).slice(-2);
  //       }).join('');
  //     });
  // } /* end sha256() */

  function derive(password, salt, algorithm, iterations) { // key derivation using 100k pbkdf w/sha1
    var passphraseKey = new TextEncoder().encode(password),
      saltBuffer = new TextEncoder().encode(salt);
    return window.crypto.subtle.importKey('raw', passphraseKey, {
        name: 'PBKDF2'
      }, false, ['deriveBits', 'deriveKey'])
      .then(function (key) {
        return window.crypto.subtle.deriveKey({
          "name": 'PBKDF2',
          "salt": saltBuffer,
          "iterations": iterations,
          "hash": 'SHA-1'
        }, key, {
          "name": algorithm,
          "length": 256
        }, true, ["encrypt", "decrypt"]);
      });
    // });
  } /* end derive() */

  function dataUrlToBlob(cipherText) { // support util for converting bin arrays
    var [mainCipher, iv, authTag] = cipherText.split('--'),
      cipherArray = base64toUnitArray(mainCipher),
      authTagArray = base64toUnitArray(authTag),
      ivArray = base64toUnitArray(iv),
      bundle = new Uint8Array([...cipherArray, ...authTagArray]);
    return [bundle, ivArray];
  } /* end dataUrlToBlob() */

  function base64toUnitArray(base64String) {
    var binData = atob(base64String),
      mx = binData.length,
      i = 0,
      uiArr = new Uint8Array(mx);
    for (i; i < mx; ++i) uiArr[i] = binData.charCodeAt(i);
    return uiArr
  }
  // provide utils as methods:
  return {
    encrypt: aesEnc,
    decrypt: aesDec
  };

}));