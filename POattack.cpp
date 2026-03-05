#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

DWORD sendRequest(const std::string& ciphertext_hex) {
    DWORD statusCode = 0;
    DWORD dwSize = sizeof(DWORD);

    HINTERNET hSession = WinHttpOpen(L"Padding Oracle Attack/1.1", 
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 0;

    HINTERNET hConnect = WinHttpConnect(hSession, L"crypto-class.appspot.com", 
                                        INTERNET_DEFAULT_HTTP_PORT, 0);
    if (hConnect) {
        std::string path_str = "/po?er=" + ciphertext_hex;
        std::wstring wpath(path_str.begin(), path_str.end());

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(), 
                                                NULL, WINHTTP_NO_REFERER, 
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (hRequest) {
            if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                if (WinHttpReceiveResponse(hRequest, NULL)) {
                    WinHttpQueryHeaders(hRequest, 
                                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                                        WINHTTP_HEADER_NAME_BY_INDEX, 
                                        &statusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
                }
            }
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    return statusCode;
}

DWORD sendRequestWithRetry(const std::string& ciphertext_hex) {
    for (int retries = 0; retries < 3; ++retries) {
        DWORD status = sendRequest(ciphertext_hex);
        if (status != 0) return status;
        Sleep(500); 
    }
    return 0;
}

int main() {
    std::string target_hex = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";
    std::vector<uint8_t> ciphertext = hexToBytes(target_hex);
    
    int block_size = 16;
    int num_blocks = ciphertext.size() / block_size;
    std::string decrypted_message = "";

    std::cout << "[*] Starting Resilient Padding Oracle Attack..." << std::endl;

    for (int block = 1; block < num_blocks; ++block) {
        std::vector<uint8_t> plaintext_block(block_size, 0);
        
        for (int byte_idx = block_size - 1; byte_idx >= 0; --byte_idx) {
            uint8_t pad_value = block_size - byte_idx;
            bool found = false;

            for (int guess = 0; guess <= 255; ++guess) {
                std::vector<uint8_t> forged_ciphertext;
                std::vector<uint8_t> prev_block(ciphertext.begin() + (block - 1) * block_size, 
                                                ciphertext.begin() + block * block_size);
                
                for (int k = block_size - 1; k > byte_idx; --k) {
                    prev_block[k] = prev_block[k] ^ plaintext_block[k] ^ pad_value;
                }

                prev_block[byte_idx] = prev_block[byte_idx] ^ guess ^ pad_value;

                for (uint8_t b : prev_block) forged_ciphertext.push_back(b);
                for (int i = 0; i < block_size; ++i) {
                    forged_ciphertext.push_back(ciphertext[block * block_size + i]);
                }


                DWORD status = sendRequestWithRetry(bytesToHex(forged_ciphertext));

                if (status == 404 || status == 200) {
        
                    if (byte_idx == block_size - 1) {
                        std::vector<uint8_t> verify_ciphertext = forged_ciphertext;
                  
                        verify_ciphertext[block_size - 2] ^= 0xFF; 
                        
                        DWORD verify_status = sendRequestWithRetry(bytesToHex(verify_ciphertext));
                        if (verify_status != 404 && verify_status != 200) {
                            continue;
                        }
                    }

                    plaintext_block[byte_idx] = guess;
                    found = true;
                    std::cout << "[+] Found byte " << byte_idx << " of block " << block 
                              << ": " << (char)guess << " (0x" << std::hex << guess << std::dec << ")" << std::endl;
                    break;
                }
            }
            if (!found) {
                std::cout << "[-] Failed to find byte " << byte_idx << std::endl;
            }
        }
        
        for (uint8_t p : plaintext_block) {
            decrypted_message += (char)p;
        }
    }

    std::cout << "\n[*] Decrypted Message: " << decrypted_message << std::endl;
    return 0;
}