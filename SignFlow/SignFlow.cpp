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
Alg alg = Alg::SHA1;

// Functions declaration
std::vector<unsigned char> Hash(const wchar_t *data);
void Sign(const wchar_t *keyName, std::vector<unsigned char> digest);
const wchar_t *CreateKey();

int main()
{

	auto keyName = CreateKey();

	auto digest = Hash(L"Lorem ipsum, dolor sit amet consectetur adipisicing elit. Iste facere nobis voluptatibus at similique, qui iure deserunt perferendis fugiat vitae asperiores reprehenderit dignissimos itaque consectetur voluptatum sed alias nemo aliquid.");

	Sign(keyName, digest);

	return 0;
}

std::vector<unsigned char> Hash(const wchar_t *data)
{
	BCRYPT_ALG_HANDLE algHandle;
	NTSTATUS status;

	TITLE("Start digest generating process using bcrypt library");

	auto algorithm = ENUM::GetAlg(alg);

	status = BCryptOpenAlgorithmProvider(&algHandle, algorithm, NULL, 0);
	ERROR("Open Algorithm " << ENUM::GetAlgName(alg), status);

	DWORD size = 0;

	status = BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, (PBYTE)&size, sizeof(size), &size, 0);
	ERROR("Get hash length property", status);

	std::vector<unsigned char> digest(size);

	status = BCryptHash(algHandle, NULL, 0, (PBYTE)data, sizeof(data), digest.data(), size);
	ERROR("Creating digest", status);

	LOG("Digest: ")
	for (int i = 0; i < digest.size(); i++)
	{
		printf("%02x", digest[i]);
	}
	LOG("\n");

	BCryptCloseAlgorithmProvider(algHandle, 0);

	return digest;
}

const wchar_t *CreateKey()
{

	NCRYPT_PROV_HANDLE pHandle;
	NCRYPT_KEY_HANDLE keyHandle;

	auto keyName = L"KeyTest";

	TITLE("Start a create key process");

	auto status = NCryptOpenStorageProvider(&pHandle, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	ERROR("Open storage provider (PCP)", status);

	status = NCryptCreatePersistedKey(pHandle, &keyHandle, (type == Type::RSA ? BCRYPT_RSA_ALGORITHM : BCRYPT_ECDSA_ALGORITHM), keyName, 0, NCRYPT_OVERWRITE_KEY_FLAG);
	ERROR("Creating a RSA key", status);

	DWORD keyUsage = NCRYPT_ALLOW_SIGNING_FLAG;

	status = NCryptSetProperty(keyHandle, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), NCRYPT_PERSIST_FLAG);
	ERROR("Set a allow signing property", status);

	if (NCryptIsKeyHandle(keyHandle))
	{
		LOG("Valid!\n");
	}

	status = NCryptFinalizeKey(keyHandle, 0);
	ERROR("Finalize Key", status);

	NCryptFreeObject(keyHandle);
	NCryptFreeObject(pHandle);
	return keyName;
}

void ShowKey(NCRYPT_KEY_HANDLE keyHandle)
{
	DWORD size = 0;
	auto status = NCryptGetProperty(keyHandle, NCRYPT_NAME_PROPERTY, NULL, NULL, &size, 0);
	ERROR("First Get key name property", status);
}

void Sign(const wchar_t *keyName, std::vector<unsigned char> digest)
{
	NCRYPT_PROV_HANDLE pHandle;
	NCRYPT_KEY_HANDLE keyHandle;

	TITLE("Start a sign digest process using ncrypt library");

	auto status = NCryptOpenStorageProvider(&pHandle, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	ERROR("Open Storage Provider (PCP)", status);

	status = NCryptOpenKey(pHandle, &keyHandle, keyName, 0, 0);
	ERROR("Open a RSA key storage on the file system", status);

	DWORD size = 0;

	BCRYPT_PKCS1_PADDING_INFO info;

	info.pszAlgId = ENUM::GetAlg(alg);

	status = NCryptSignHash(keyHandle, &info, digest.data(), digest.size(), NULL, NULL, &size, BCRYPT_PAD_PKCS1);
	ERROR("First SignHash", status);

	std::vector<unsigned char> signature(size);

	status = NCryptSignHash(keyHandle, &info, digest.data(), digest.size(), signature.data(), size, &size, BCRYPT_PAD_PKCS1);
	ERROR("Second SignHash", status);

	LOG("Signature: \n");
	FOR(size)
	printf("%02x", signature[i]);
	LOG("\n");
	LOG("\n");

	status = NCryptVerifySignature(keyHandle, &info, digest.data(), digest.size(), signature.data(), signature.size(), BCRYPT_PAD_PKCS1);
	ERROR("Verify Signature", status);

	NCryptFreeObject(keyHandle);
	NCryptFreeObject(pHandle);
}
