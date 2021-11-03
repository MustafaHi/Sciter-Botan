//| Sciter-Botan 2.0+
//| https://github.com/MustafaHi/Sciter-Botan

import { loadLibrary } from "@sciter";

const Botan = globalThis.Botan || loadLibrary("sciter-botan");


export function password(method, data, hash = "") {
    return new Promise((resolve, reject) => {
        function CB(data, pass = true) { pass ? resolve(data) : reject(data); }
        Botan.passwordN(CB, method, data, hash);
    });
}

export function cipher(method, data, key, iv = "") {
    return new Promise((resolve, reject) => {
        function CB(data, pass = true) { pass ? resolve(data) : reject(data); }
        Botan.cipherN(CB, method, data, key, iv);
    });
}

export function decipher(method, data, key, iv) {
    return new Promise((resolve, reject) => {
        function CB(data, pass = true) { pass ? resolve(data) : reject(data); }
        Botan.decipherN(CB, method, data, key, iv);
    });
}

export function encode() { return Botan.encode(...arguments); }
export function decode() { return Botan.decode(...arguments); }
export function hash()   { return Botan.hash(...arguments); }
export function iv()     { return Botan.iv(...arguments); }
