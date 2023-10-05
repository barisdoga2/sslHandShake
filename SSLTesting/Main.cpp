#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

EVP_PKEY* convertStringToEVP_PKEY(const std::string& publicKeyString) 
{
    const char* publicKeyData = publicKeyString.c_str();

    // Load the public key from a string
    BIO* bio = BIO_new_mem_buf((void*)publicKeyData, -1); // -1 means BIO should calculate the string length
    if (bio == NULL) {
        // Handle error (e.g., out of memory)
        return NULL;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        // Handle error (e.g., incorrect key format)
        return NULL;
    }

    return pkey;
}

bool ReadPublicKey(const EVP_PKEY* key, std::string& publicKeyOut)
{
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio != nullptr)
    {
        int bio_write = PEM_write_bio_PUBKEY(bio, key);
        if (bio_write != 0)
        {
            char buffer[1000];
            int bytes = BIO_read(bio, buffer, sizeof(buffer));
            for (int i = 0; i < bytes; i++)
                publicKeyOut += buffer[i];
            return true;
        }
        else
        {
            std::cout << "Failed to Get Public Key!" << std::endl;
            return false;
        }
    }
    else
    {
        std::cout << "New BIO Failed!" << std::endl;
        return false;
    }
    BIO_free(bio);
    return true;
}

std::string Encrypt(EVP_PKEY* key, const std::string& data)
{
    std::string encryptedData;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ctx);

    size_t ciphertextLen = 0;
    EVP_PKEY_encrypt(ctx, NULL, &ciphertextLen, (const unsigned char*)data.c_str(), data.size());
    unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(ciphertextLen);
    EVP_PKEY_encrypt(ctx, ciphertext, &ciphertextLen, (const unsigned char*)data.c_str(), data.size());
    encryptedData.assign((char*)ciphertext, ciphertextLen);

    return encryptedData;
}

std::string Decrypt(EVP_PKEY* key, const std::string& data)
{
    std::string decryptedData;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_decrypt_init(ctx);

    size_t ciphertextLen = 0;
    EVP_PKEY_decrypt(ctx, NULL, &ciphertextLen, (const unsigned char*)data.c_str(), data.size());
    unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(ciphertextLen);
    EVP_PKEY_decrypt(ctx, ciphertext, &ciphertextLen, (const unsigned char*)data.c_str(), data.size());
    decryptedData.assign((char*)ciphertext, ciphertextLen);

    return decryptedData;
}

bool GenerateRSAKey(EVP_PKEY_CTX** ctx, EVP_PKEY** key)
{
    *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(*ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(*ctx, 2048);
    EVP_PKEY_keygen(*ctx, &*key);
    return true;
}

class Server {
public:
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* key = nullptr;
    std::string publicKey = "";

    EVP_PKEY* clientKey = nullptr;

    Server()
    {
        GenerateRSAKey(&ctx, &key);
        ReadPublicKey(key, publicKey);
    }

    void ClientPublicKeyReceive(std::string clientPublicKey)
    {
        clientKey = convertStringToEVP_PKEY(clientPublicKey);
    }

    std::string PrepareDataToClient(std::string data)
    {
        return Encrypt(clientKey, data);
    }

    std::string ReceiveDataFromClient(std::string data)
    {
        return Decrypt(key, data);
    }
};


class Client {
public:
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* key = nullptr;
    std::string publicKey;

    EVP_PKEY* serverKey = nullptr;

    Client()
    {
        GenerateRSAKey(&ctx, &key);
        ReadPublicKey(key, publicKey);
    }

    void ServerPublicKeyReceive(std::string serverPublicKey)
    {
        serverKey = convertStringToEVP_PKEY(serverPublicKey);
    }

    std::string PrepareDataToServer(std::string data)
    {
        return Encrypt(serverKey, data);
    }

    std::string ReceiveDataFromServer(std::string data)
    {
        return Decrypt(key, data);
    }
};

int main()
{
    Server* server = new Server();
    Client* client = new Client();

    server->ClientPublicKeyReceive(client->publicKey);
    client->ServerPublicKeyReceive(server->publicKey);

    std::string encrpytedData = server->PrepareDataToClient("Hello Client!");
    std::string decrpytedData = client->ReceiveDataFromServer(encrpytedData);

    std::string encrpytedData2 = client->PrepareDataToServer("Hello Server!");
    std::string decrpytedData2 = server->ReceiveDataFromClient(encrpytedData2);

	return 0;
}