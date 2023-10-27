#pragma once

enum Type
{
	RSA,
	ECC
};
enum Alg {
	SHA1,
	SHA256,
};

namespace ENUM {
	const wchar_t* GetAlg(Alg alg) {
		switch (alg)
		{
		case SHA1:
			return BCRYPT_SHA1_ALGORITHM;
		case SHA256:
			return BCRYPT_SHA256_ALGORITHM;
			break;
		default:
			break;
		}
	}
	std::string GetAlgName(Alg alg) {
		switch (alg)
		{
		case SHA1:
			return "SHA1";
		case SHA256:
			return "SHA256";
		default:
			break;
		}
	}
}