#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

#include <bcrypt.h>
#include <ncrypt.h>

#include "include/enum.h"
#include "include/Utils/macros.h"

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

Type type = Type::RSA;

std::vector<unsigned char> Hash(const wchar_t* data) {
	BCRYPT_ALG_HANDLE algHandle;

	NTSTATUS status;

	status = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	Error("Open Algorithm\n", status);

	DWORD size = 0;

	status = BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, (PBYTE)&size, sizeof(size), &size, 0);
	Error("Get property\n", status);

	std::vector<unsigned char> digest(size);

	status = BCryptHash(algHandle, NULL, 0, (PBYTE)data, sizeof(data), digest.data(), size);
	Error("Creating digest\n", status);

	for (int i = 0; i < digest.size(); i++) {
		printf("%02x", digest[i]);
	}
	LOG("\n");

	BCryptCloseAlgorithmProvider(algHandle, 0);

	return digest;
}

void CreateKey() {

	NCRYPT_PROV_HANDLE pHandle;
	NCRYPT_KEY_HANDLE keyHandle;

	auto status = NCryptOpenStorageProvider(&pHandle, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	Error("Open Storage Provider", status);

	status = NCryptCreatePersistedKey(pHandle, &keyHandle, (type == Type::RSA ? BCRYPT_RSA_ALGORITHM : BCRYPT_ECDSA_ALGORITHM), L"Mamaco", 0, NCRYPT_OVERWRITE_KEY_FLAG);
	Error("Create Key", status);

	DWORD keyUsage = NCRYPT_ALLOW_SIGNING_FLAG;

	status = NCryptSetProperty(keyHandle, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), NCRYPT_PERSIST_FLAG);
	Error("Set Property", status);

	if (NCryptIsKeyHandle(keyHandle)) {
		LOG("Valid!\n");
	}
	else {
		LOG("Not Valid!\n")
			exit(-1);
	}

	status = NCryptFinalizeKey(keyHandle, 0);
	Error("Finalize Key", status);

	NCryptFreeObject(keyHandle);
	NCryptFreeObject(pHandle);
}

void Sign() {
	NCRYPT_PROV_HANDLE pHandle;
	NCRYPT_KEY_HANDLE keyHandle;

	auto status = NCryptOpenStorageProvider(&pHandle, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	Error("Open Storage Provider\n", status);

	status = NCryptOpenKey(pHandle, &keyHandle, L"Mamaco", 0, 0);
	Error("Open Key\n", status);

	if (NCryptIsKeyHandle(keyHandle)) {
		LOG("Valid!\n");
	}

	auto data = L"Mamaco";

	auto digest = Hash(data);

	DWORD size = 0;

	BCRYPT_PKCS1_PADDING_INFO info;
	info.pszAlgId = (type == Type::RSA ? BCRYPT_SHA256_ALGORITHM : BCRYPT_ECDSA_P256_ALGORITHM);

	auto padding = (type == Type::RSA ? BCRYPT_PAD_PKCS1 : 0);

	status = NCryptSignHash(keyHandle, &info, digest.data(), digest.size(), NULL, NULL, &size, padding);
	Error("First SignHash\n", status);

	std::vector<unsigned char> signature(size);

	status = NCryptSignHash(keyHandle, &info, digest.data(), digest.size(), signature.data(), size, &size, padding);
	Error("Second SignHash\n", status);

	LOG("Signature: \n");
	FOR(size) printf("%02x", signature[i]);
	LOG("\n");

	status = NCryptVerifySignature(keyHandle, &info, digest.data(), digest.size(), signature.data(), signature.size(), padding);
	Error("Verify Signature\n", status);

	NCryptFreeObject(keyHandle);
	NCryptFreeObject(pHandle);
}

int main() {
	Sign();
	//CreateKey();
	return 0;
}