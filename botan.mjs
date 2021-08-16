import { loadLibrary } from "@sciter";

globalThis.Botan = loadLibrary("sciter-botan");

Botan.password = function(method, data, hash = "") {
    return new Promise((resolve, reject) => {
        function CB(data, pass = true) { pass ? resolve(data) : reject(data); }
        Botan.passwordN(CB, method, data, hash);
    });
}

Botan.cipher = function(method, data, key, iv = "") {
    return new Promise((resolve, reject) => {
        function CB(data, pass = true) { pass ? resolve(data) : reject(data); }
        Botan.cipherN(CB, method, data, key, iv);
    });
}

Botan.decipher = function(method, data, key, iv) {
    return new Promise((resolve, reject) => {
        function CB(data, pass = true) { pass ? resolve(data) : reject(data); }
        Botan.decipherN(CB, method, data, key, iv);
    });
}
