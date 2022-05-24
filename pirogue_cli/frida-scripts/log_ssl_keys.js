/**
 * Dumps TLS v1.2 and v1.3 keys in the NSS key log format (https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).
 * 
 * This script is based on the work of Hugo Tunius, @k0nser: https://hugotunius.se/2020/08/07/stealing-tls-sessions-keys-from-ios-apps.html
 * 
 * License: MIT
 */

'use strict';

function _log_ssl_keys(SSL_CTX_new, SSL_CTX_set_keylog_callback) {
    function log_key(ssl, line) {
        const s_line = new NativePointer(line).readCString();
        console.log(s_line);
        const msg = {
            'type': 'ssl_key_log',
            'dump': 'sslkeylog.txt',
            'data_type': 'plain',
            'data': s_line
        }
        send(msg);
    }
    const keylogCallback = new NativeCallback(log_key, 'void', ['pointer', 'pointer'])
    Interceptor.attach(SSL_CTX_new, {
        onLeave: function(retval) {
            const ssl = new NativePointer(retval);
            if (!ssl.isNull()) {
                const SSL_CTX_set_keylog_callbackFn = new NativeFunction(SSL_CTX_set_keylog_callback, 'void', ['pointer', 'pointer']);
                SSL_CTX_set_keylog_callbackFn(ssl, keylogCallback);
            }
        }
    });
}

function log_ssl_keys() {
    _log_ssl_keys(
        Module.findExportByName('libssl.so', 'SSL_CTX_new'),
        Module.findExportByName('libssl.so', 'SSL_CTX_set_keylog_callback')
    );
}

try {
    r2frida.pluginRegister('log_ssl_keys', log_ssl_keys);
} catch (e) {}

try {
    rpc.exports['logSslKeys'] = log_ssl_keys;
} catch (e) {}