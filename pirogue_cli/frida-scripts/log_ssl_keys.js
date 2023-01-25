/**
 * Dumps TLS v1.2 and v1.3 keys in the NSS key log format (https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).
 *
 * This script is based on the work of Hugo Tunius, @k0nser: https://hugotunius.se/2020/08/07/stealing-tls-sessions-keys-from-ios-apps.html as well as the work of Walter J., @709924470: https://gist.github.com/709924470/9447431354bdbf997a07665f7a2bcf9f.
 *
 * Standalone usage (outside of pirogue-cli / testing purpose) can easily be achieved with:
 * $ frida -U -f com.example -l ./pirogue_cli/frida-scripts/log_ssl_keys.js --pause
 * [Phone:com.example ]-> log_ssl_keys();
 * [Phone:com.example ]-> %resume
 *
 * License: MIT
 */

'use strict';

function _log_ssl_keys(SSL_CTX_new, SSL_CTX_set_keylog_callback) {
    if (!SSL_CTX_new || !SSL_CTX_set_keylog_callback) {
        console.warn('_log_ssl_keys called with NULL pointers, ignoring.')
        return -1;
    }

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

    return 0;
}

function hookNative(path){
    console.log(path);
}

function log_ssl_keys() {
    // Bind onto libssl
    _log_ssl_keys(
        Module.findExportByName('libssl.so', 'SSL_CTX_new'),
        Module.findExportByName('libssl.so', 'SSL_CTX_set_keylog_callback')
    );

    // GoogleMobileServices (GMS) are pushing updates to the security provider
    // Therefore, for apps relying on this Provider, they will not use the
    // libssl.so from the system but instead the libssl bundled into the
    // conscrypt module shipped by GMS.
    // See https://android.googlesource.com/platform/external/conscrypt/+/b578b39/src/main/java/org/conscrypt/NativeCrypto.java#49
    // See https://developer.android.com/training/articles/security-gms-provider
    const CONSCRYPT_LIBS = [
        'libconscrypt_gmscore_jni.so',
        'libconscrypt_jni.so',
    ];
    const ANDROID_DLOPEN = ['android_dlopen_ext', 'dlopen'];
    for (let conscrypt of CONSCRYPT_LIBS) {
        // We try to hook directly, if the module has already been logged
        let has_attached = _log_ssl_keys(
            Module.findExportByName(conscrypt, 'SSL_CTX_new'),
            Module.findExportByName(conscrypt, 'SSL_CTX_set_keylog_callback')
        );
        if (has_attached == 0) {
            console.log('Hooked loaded conscrypt module ' + conscrypt);
            continue;
        }

        // Otherwise, we hook for dlopen call to hook the library whenever (if
        // it is indeed used by the app) loeaded
        for (let dlopen of ANDROID_DLOPEN) {
            Interceptor.attach(Module.findExportByName(null, dlopen), {
                onEnter: function (args) {
                    this.flag = false;
                    var path = Memory.readUtf8String(args[0]);
                    if (path.indexOf(conscrypt) > 0) {
                        console.log('Hooking loaded conscrypt module ' + conscrypt)
                        this.flag = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.flag) {
                        _log_ssl_keys(
                            Module.findExportByName(conscrypt, 'SSL_CTX_new'),
                            Module.findExportByName(conscrypt, 'SSL_CTX_set_keylog_callback')
                        );
                    }
                }
            });
        }
    }
}

try {
    r2frida.pluginRegister('log_ssl_keys', log_ssl_keys);
} catch (e) {}

try {
    rpc.exports['logSslKeys'] = log_ssl_keys;
} catch (e) {}

