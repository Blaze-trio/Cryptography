#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

const int BLOCK_SIZE = 1024;
const int HASH_SIZE = 32; 

bool compute_sha256(const std::vector<unsigned char>& data, unsigned char* output) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool result = false;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error: CryptAcquireContext failed." << std::endl;
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "Error: CryptCreateHash failed. Ensure your Windows SDK supports SHA256." << std::endl;
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, data.data(), (DWORD)data.size(), 0)) {
        std::cerr << "Error: CryptHashData failed." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    DWORD hashLen = HASH_SIZE;
    if (CryptGetHashParam(hHash, HP_HASHVAL, output, &hashLen, 0)) {
        result = true;
    } else {
        std::cerr << "Error: CryptGetHashParam failed." << std::endl;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

std::string to_hex(const unsigned char* hash, int length) {
    std::stringstream ss;
    for (int i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main() {

    std::string filename = "6.1.intro.mp4";


    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        std::cerr << "Make sure the video file is in the same folder as the .exe!" << std::endl;
        return 1;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> fileBuffer(fileSize);
    if (!file.read((char*)fileBuffer.data(), fileSize)) {
        std::cerr << "Error: Could not read file data." << std::endl;
        return 1;
    }
    file.close();

    int numBlocks = (int)((fileSize + BLOCK_SIZE - 1) / BLOCK_SIZE);
    unsigned char currentHash[HASH_SIZE];
    bool isLastBlock = true;


    for (int i = numBlocks - 1; i >= 0; --i) {
        int start = i * BLOCK_SIZE;
        int currentBlockSize = (int)std::min((long long)BLOCK_SIZE, (long long)(fileSize - start));

        std::vector<unsigned char> bufferToHash;
        bufferToHash.insert(bufferToHash.end(), 
                            fileBuffer.begin() + start, 
                            fileBuffer.begin() + start + currentBlockSize);

        if (!isLastBlock) {
            bufferToHash.insert(bufferToHash.end(), currentHash, currentHash + HASH_SIZE);
        }

        if (!compute_sha256(bufferToHash, currentHash)) {
            return 1;
        }

        isLastBlock = false;
    }

    std::cout << "The computed h0 is: " << to_hex(currentHash, HASH_SIZE) << std::endl;
    
    std::cout << "\nPress Enter to exit...";
    std::cin.get(); 

    return 0;
}