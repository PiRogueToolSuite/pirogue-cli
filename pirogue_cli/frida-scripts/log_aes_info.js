'use strict';

function log_aes_info(pid, process) {

    var use_single_byte = false;
    var complete_bytes = new Array();
    var index = 0;


    var secretKeySpecDef = Java.use('javax.crypto.spec.SecretKeySpec');

    var ivParameterSpecDef = Java.use('javax.crypto.spec.IvParameterSpec');

    var cipherDef = Java.use('javax.crypto.Cipher');

    var cipherDoFinal_1 = cipherDef.doFinal.overload();
    var cipherDoFinal_2 = cipherDef.doFinal.overload('[B');
    var cipherDoFinal_3 = cipherDef.doFinal.overload('[B', 'int');
    var cipherDoFinal_4 = cipherDef.doFinal.overload('[B', 'int', 'int');
    var cipherDoFinal_5 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B');
    var cipherDoFinal_6 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B', 'int');

    var cipherUpdate_1 = cipherDef.update.overload('[B');
    var cipherUpdate_2 = cipherDef.update.overload('[B', 'int', 'int');
    var cipherUpdate_3 = cipherDef.update.overload('[B', 'int', 'int', '[B');
    var cipherUpdate_4 = cipherDef.update.overload('[B', 'int', 'int', '[B', 'int');

    var secretKeySpecDef_init_1 = secretKeySpecDef.$init.overload('[B', 'java.lang.String');

    var secretKeySpecDef_init_2 = secretKeySpecDef.$init.overload('[B', 'int', 'int', 'java.lang.String');

    var ivParameterSpecDef_init_1 = ivParameterSpecDef.$init.overload('[B');

    var ivParameterSpecDef_init_2 = ivParameterSpecDef.$init.overload('[B', 'int', 'int');

    secretKeySpecDef_init_1.implementation = function(arr, alg) {
        var key = b2s(arr);
        const msg = {
            'type': 'aes_info_log',
            'dump': 'aes_info.json',
            'data_type': 'json',
            'pid': pid,
            'process': process,
            'timestamp': Date.now(),
            'data': {
                'iv': '',
                'alg': alg,
                'in': '',
                'out': '',
                'key': toHexString(arr)
            }
        }
        send(msg)
        // console.log("Creating " + alg + " secret key, plaintext:\\n" + hexdump(key));
        return secretKeySpecDef_init_1.call(this, arr, alg);
    }

    secretKeySpecDef_init_2.implementation = function(arr, off, len, alg) {
        var key = b2s(arr);
        const msg = {
            'type': 'aes_info_log',
            'dump': 'aes_info.json',
            'data_type': 'json',
            'pid': pid,
            'process': process,
            'timestamp': Date.now(),
            'data': {
                'iv': '',
                'alg': alg,
                'in': '',
                'out': '',
                'key': toHexString(arr)
            }
        }
        send(msg)
        // console.log("Creating " + alg + " secret key, plaintext:\\n" + hexdump(key));
        return secretKeySpecDef_init_2.call(this, arr, off, len, alg);
    }

    cipherDoFinal_1.implementation = function() {
        var ret = cipherDoFinal_1.call(this);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_2.implementation = function(arr) {
        addtoarray(arr);
        var ret = cipherDoFinal_2.call(this, arr);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_3.implementation = function(arr, a) {
        addtoarray(arr);
        var ret = cipherDoFinal_3.call(this, arr, a);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_4.implementation = function(arr, a, b) {
        addtoarray(arr);
        var ret = cipherDoFinal_4.call(this, arr, a, b);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_5.implementation = function(arr, a, b, c) {
        addtoarray(arr);
        var ret = cipherDoFinal_5.call(this, arr, a, b, c);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_6.implementation = function(arr, a, b, c, d) {
        addtoarray(arr);
        var ret = cipherDoFinal_6.call(this, arr, a, b, c, d);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, c);
        return ret;
    }

    cipherUpdate_1.implementation = function(arr) {
        addtoarray(arr);
        return cipherUpdate_1.call(this, arr);
    }

    cipherUpdate_2.implementation = function(arr, a, b) {
        addtoarray(arr);
        return cipherUpdate_2.call(this, arr, a, b);
    }

    cipherUpdate_3.implementation = function(arr, a, b, c) {
        addtoarray(arr);
        return cipherUpdate_3.call(this, arr, a, b, c);
    }

    cipherUpdate_4.implementation = function(arr, a, b, c, d) {
        addtoarray(arr);
        return cipherUpdate_4.call(this, arr, a, b, c, d);
    }

    function info(iv, alg, plain, encoded) {
        const msg = {
            'type': 'aes_info_log',
            'dump': 'aes_info.json',
            'data_type': 'json',
            'pid': pid,
            'process': process,
            'timestamp': Date.now(),
            'data': {
                'iv': toHexString(iv),
                'alg': alg,
                'in': toHexString(plain),
                'out': toHexString(encoded),
                'key': ''
            }
        }
        send(msg);
        complete_bytes = [];
        index = 0;
    }

    function toHexString(byteArray) {
        if (byteArray === null)
            return '';
        return Array.from(byteArray, function(byte) {
          return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('')
      }

    function hexdump(buffer, blockSize) {
        blockSize = blockSize || 16;
        var lines = [];
        var hex = "0123456789ABCDEF";
        for (var b = 0; b < buffer.length; b += blockSize) {
            var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
            var addr = ("0000" + b.toString(16)).slice(-4);
            var codes = block.split('').map(function(ch) {
                var code = ch.charCodeAt(0);
                return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
            }).join("");
            codes += "   ".repeat(blockSize - block.length);
            var chars = block.replace(/[\\x00-\\x1F\\x20]/g, '.');
            chars += " ".repeat(blockSize - block.length);
            lines.push(addr + " " + codes + "  " + chars);
        }
        return lines.join("\\n");
    }

    function b2s(array) {
        var result = "";
        if (array === null)
            return result;
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }

    function addtoarray(arr) {
        for (var i = 0; i < arr.length; i++) {
            complete_bytes[index] = arr[i];
            index = index + 1;
        }
    }
}

try {
    r2frida.pluginRegister('log_aes_info', log_aes_info);
} catch (e) {}

try {
    rpc.exports['logAesInfo'] = log_aes_info
} catch (e) {}

