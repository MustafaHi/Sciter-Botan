// Sciter Botan v2.0
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
#include "sciter-x-threads.h"


class botan : public sciter::om::asset<botan> {

	// Helper functions 
	auto toString(Botan::secure_vector<uint8_t> data) { return std::string(data.begin(), data.end()); }
	auto toString(std::vector<uint8_t> data)		   { return std::string(data.begin(), data.end()); }
	auto toString(std::string data)                   { return sciter::value(aux::utf2w(data).chars()); }

	// Hash : https://botan.randombit.net/handbook/api_ref/hash.html
	sciter::value hash(std::string method, std::string data) {
		if (method.empty() || data.empty()) return "Error: Invalid parameters. (string: method, string: data)";
		std::unique_ptr<Botan::HashFunction> func(Botan::HashFunction::create(method));
		if (!func) return "Error: Invalid hash method. refer to https://botan.randombit.net/handbook/api_ref/hash.html";
		return Botan::hex_encode(func->process(data));
	}

	// Password Hashing : https://botan.randombit.net/handbook/api_ref/passhash.html
	sciter::value passwordN(sciter::value CB, std::string method, std::string data, std::string hash = "") {
		struct thread_params { sciter::value CB; std::string method; std::string data; std::string hash; };
		thread_params params;
					  params.CB		= CB;
					  params.method = method;
					  params.data	= data;
					  params.hash	= hash;

		sciter::thread([&](thread_params params)
		{
			Botan::AutoSeeded_RNG rng;
			if (params.method == "argon") {
				params.CB.call(Botan::argon2_generate_pwhash(params.data.c_str(), params.data.length(), rng, 1, 5120, 100));
				return;
			}
			else if (params.method == "check-argon") {
				if  (params.hash.empty()) params.CB.call("Error: You must provide Hash as third argument", false);
				else params.CB.call(Botan::argon2_check_pwhash(params.data.c_str(), params.data.length(), params.hash));
				return;
			}
			else if (params.method == "bcrypt") {
				params.CB.call(Botan::generate_bcrypt(params.data, rng));
				return;
			}
			else if (params.method == "check-bcrypt") {
				if  (params.hash.empty()) params.CB.call("Error: You must provide Hash as third argument", false);
				else params.CB.call(Botan::check_bcrypt(params.data, params.hash));
				return;
			}
			params.CB.call("Error: Specify method, [\"argon\", check-argon, \"bcrypt\", check-bcrypt]", false);
		}, params);

		return sciter::value();
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
	sciter::value crypter(sciter::value CB, Botan::Cipher_Dir dir, std::string method, std::string data, std::string key, std::string key_iv = "") {
		struct thread_params { sciter::value CB; Botan::Cipher_Dir dir; std::string method; std::string data; std::string key; std::string key_iv; };
		thread_params params;
					  params.CB		= CB;
					  params.dir	= dir;
					  params.method	= method;
					  params.data	= data;
					  params.key	= key;
					  params.key_iv	= key_iv;


		sciter::thread([&](thread_params params)
		{
			Botan::AutoSeeded_RNG rng;
			std::unique_ptr<Botan::Cipher_Mode> func = Botan::Cipher_Mode::create(params.method, params.dir);
			if (!func) { params.CB.call("Error: Invalid Cipher algorithm (method). refer to https://botan.randombit.net/handbook/api_ref/block_cipher.html", false); return; }

			Botan::SymmetricKey k(params.key);
			func->set_key(k);

			Botan::InitializationVector iv;
			params.key_iv.empty() ? iv = rng.random_vec(func->default_nonce_length()) : iv = Botan::hex_decode(params.key_iv);

			Botan::secure_vector<uint8_t> d(params.data.begin(), params.data.end());
			if (params.dir == Botan::Cipher_Dir::DECRYPTION) {
				std::vector<uint8_t> a = Botan::hex_decode(params.data);
				d.assign(a.begin(), a.end());
			}

			func->start(iv.bits_of());
			func->finish(d);

			sciter::value v = sciter::value::make_map();
			if (params.dir == Botan::Cipher_Dir::DECRYPTION) {
				v.set_item("data", toString(d));
				v.set_item("iv", iv.to_string());
			}
			else {
				v.set_item("data", toString(Botan::hex_encode(d)));
				v.set_item("iv", iv.to_string());
			}
			
			params.CB.call(v);
		}, params);

		return sciter::value();
	}
	sciter::value cipherN(sciter::value CB, std::string method, std::string data, std::string key, std::string iv = "") {
		return crypter(CB, Botan::Cipher_Dir::ENCRYPTION, method, data, key, iv);
	}
	sciter::value decipherN(sciter::value CB, std::string method, std::string data, std::string key, std::string iv) {
		return crypter(CB, Botan::Cipher_Dir::DECRYPTION, method, data, key, iv);
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
		SOM_PASSPORT_FLAGS(SOM_EXTENDABLE_OBJECT)
		SOM_FUNCS(
			SOM_FUNC(hash),
			SOM_FUNC(passwordN),
			SOM_FUNC(encode),
			SOM_FUNC(decode),
			SOM_FUNC(cipherN),
			SOM_FUNC(decipherN),
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
