// Sciter Botan v1.0
// https://github.com/MustafaHi/Sciter-Botan


#include "botan/hash.h"
#include "botan/argon2.h"
#include "botan/bcrypt.h"
#include "botan/hex.h"
#include "botan/base64.h"
#include "botan/rng.h"
#include "botan/auto_rng.h"
#include "botan/cipher_mode.h"


#include "sciter-x.h"


class botan : public sciter::om::asset<botan> {
	// Helper functions 
	sciter::value toString(Botan::secure_vector<uint8_t> data) { return std::string(data.begin(), data.end()); }
	sciter::value toString(std::vector<uint8_t> data)		   { return std::string(data.begin(), data.end()); }

	// Hash : https://botan.randombit.net/handbook/api_ref/hash.html
	sciter::value hash(std::string method, std::string data) {
		if (method.empty() || data.empty()) return "Error: Invalid parameters. (string: method, string: data)";
		std::unique_ptr<Botan::HashFunction> func(Botan::HashFunction::create(method));
		if (!func) return "Error: Invalid hash method. refer to https://botan.randombit.net/handbook/api_ref/hash.html";
		return Botan::hex_encode(func->process(data));
	}

	// Password Hashing : https://botan.randombit.net/handbook/api_ref/passhash.html
	sciter::value password(std::string method, std::string data, std::string hash = "") {
		if (method.empty() || data.empty()) return "Error: Invalid parameters. (string: method, string: password [, string: hash])";
		Botan::AutoSeeded_RNG rng;
		if (method == "argon") {
			return Botan::argon2_generate_pwhash(data.c_str(), data.length(), rng, 1, 5120, 100);
		}
		else if (method == "check-argon") {
			if (hash.empty()) return "Error: You must provide Hash as third argument";
			return Botan::argon2_check_pwhash(data.c_str(), data.length(), hash);
		}
		else if (method == "bcrypt") {
			return Botan::generate_bcrypt(data, rng);
		}
		else if (method == "check-bcrypt") {
			if (hash.empty()) return "Error: You must provide Hash as third argument";
			return Botan::check_bcrypt(data, hash);
		}
		return "Error: Specify method, [\"argon\", check-argon, \"bcrypt\", check-bcrypt]";
	}

	// Encoding / Decoding
	sciter::value codec(bool encode, std::string method, std::string data) {
		if (method.empty() || data.empty()) return "Error: Invalid parameters. (string: method, string: data)";
		if (encode) {
			if (method == "hex") {
				return Botan::hex_encode(std::vector<uint8_t>(data.begin(), data.end()));
			}
			else if (method == "base64") {
				return Botan::base64_encode(std::vector<uint8_t>(data.begin(), data.end()));
			}
		}
		else {
			if (method == "hex") {
				return toString(Botan::hex_decode(data));
			}
			else if (method == "base64") {
				return toString(Botan::base64_decode(data));
			}
		}
		return "Error: Specify method, [\"hex\", \"base64\"]";
	}
	sciter::value encode(std::string method, std::string data) {
		return codec(true, method, data);
	}
	sciter::value decode(std::string method, std::string data) {
		return codec(false, method, data);
	}
	
	// Crypto
	sciter::value crypter(Botan::Cipher_Dir dir, std::string method, std::string data, std::string key, std::string key_iv = "") {
		if (method.empty() || data.empty() || key.empty()) return "Error: Invalid parameters. (string: method, string: data, string: key [, string: iv])";
		Botan::AutoSeeded_RNG rng;
		std::unique_ptr<Botan::Cipher_Mode> func = Botan::Cipher_Mode::create(method, dir);
			if (!func) return "Error: Invalid Cipher algorithm (method). refer to https://botan.randombit.net/handbook/api_ref/block_cipher.html";

			//if (!func->valid_keylength(key.length())) { return "Error: Invalid key length"; }
		Botan::SymmetricKey k(key);
			
		func->set_key(k);

		Botan::InitializationVector iv;
		key_iv.empty() ? iv = rng.random_vec(func->default_nonce_length()) : iv = Botan::hex_decode(key_iv);
			//if (!func->valid_nonce_length(iv.length())) { return printf("Error: Invalid nonce/iv length must be %i", func->default_nonce_length()); }

		Botan::secure_vector<uint8_t> d(data.begin(), data.end());
		if (dir == Botan::Cipher_Dir::DECRYPTION) {
			std::vector<uint8_t> a = Botan::hex_decode(data);
			d.assign(a.begin(), a.end());
		}

		func->start(iv.bits_of());
		func->finish(d);
		
		sciter::value v = sciter::value::make_map();
		if (dir == Botan::Cipher_Dir::DECRYPTION) {
			v.set_item("data", toString(d));
			v.set_item("iv", iv.to_string());
		}
		else {
			v.set_item("data", Botan::hex_encode(d));
			v.set_item("iv", iv.to_string());
		}
		return v;
	}
	sciter::value cipher(std::string method, std::string data, std::string key, std::string iv = "") {
		return crypter(Botan::Cipher_Dir::ENCRYPTION, method, data, key, iv);
	}
	sciter::value decipher(std::string method, std::string data, std::string key, std::string iv) {
		return crypter(Botan::Cipher_Dir::DECRYPTION, method, data, key, iv);
	}

	// Utilities
	sciter::value iv(std::string method = "AES-256/GCM") {
		Botan::AutoSeeded_RNG rng;
		std::unique_ptr<Botan::Cipher_Mode> func = Botan::Cipher_Mode::create(method, Botan::Cipher_Dir::ENCRYPTION);
		if (!func) return "Error: Invalid Cipher algorithm. refer to https://botan.randombit.net/handbook/api_ref/cipher_modes.html#available-unauthenticated-cipher-modes";
		Botan::InitializationVector iv(rng.random_vec(func->default_nonce_length()));
		return iv.to_string();
	}
	//sciter::value iv(int size) {
	//	Botan::AutoSeeded_RNG rng;
	//	Botan::secure_vector<uint8_t> iv(rng.random_vec(size));
	//	return Botan::hex_encode(iv);
	//}


	SOM_PASSPORT_BEGIN_EX(Botan, botan)
		SOM_FUNCS(
			SOM_FUNC(hash),
			SOM_FUNC(password),
			SOM_FUNC(encode),
			SOM_FUNC(decode),
			SOM_FUNC(cipher),
			SOM_FUNC(decipher),
			SOM_FUNC(iv)
		)
	SOM_PASSPORT_END

};


SBOOL SCAPI SciterLibraryInit(ISciterAPI* psapi, SCITER_VALUE* plibobject)
{
	_SAPI(psapi);
	static sciter::om::hasset<botan> botan_root = new botan();
	*plibobject = sciter::value::wrap_asset(botan_root);
	return TRUE;
}
