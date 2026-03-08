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
    // Ciphertext: 4 blocks of 16 bytes (Block 0 = IV, Blocks 1-3 = ciphertext)
    std::string target_hex = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";
    std::vector<uint8_t> ciphertext = hexToBytes(target_hex);

    const int BLOCK_SIZE = 16;
    int num_blocks = (int)ciphertext.size() / BLOCK_SIZE;
    std::string decrypted_message = "";

    std::cout << "[*] Starting Padding Oracle Attack (" << num_blocks - 1
              << " ciphertext blocks to decrypt)..." << std::endl;

    // Decrypt each ciphertext block (block 1 .. num_blocks-1)
    // using the previous block (or IV) as the forged prev-block
    for (int block = 1; block < num_blocks; ++block) {
        std::vector<uint8_t> plaintext_block(BLOCK_SIZE, 0);
        std::cout << "\n[*] Decrypting block " << block << "..." << std::endl;

        // Recover bytes from right to left: index 15 down to 0
        for (int byte_idx = BLOCK_SIZE - 1; byte_idx >= (block == 1 ? 14 : 0); --byte_idx) {
            // PKCS#7 target padding value for this position
            uint8_t pad_value = (uint8_t)(BLOCK_SIZE - byte_idx);
            bool found = false;

            for (int guess = 0; guess <= 255; ++guess) {
                // Start from the real previous block (block-1)
                std::vector<uint8_t> prev_block(
                    ciphertext.begin() + (block - 1) * BLOCK_SIZE,
                    ciphertext.begin() +  block      * BLOCK_SIZE);

                // Fix up bytes we've already recovered so they decrypt to pad_value
                for (int k = byte_idx + 1; k < BLOCK_SIZE; ++k) {
                    prev_block[k] ^= plaintext_block[k] ^ pad_value;
                }

                // Inject our guess for position byte_idx
                prev_block[byte_idx] ^= guess ^ pad_value;

                // Forged ciphertext = [modified prev block] + [current cipher block]
                std::vector<uint8_t> forged;
                forged.insert(forged.end(), prev_block.begin(), prev_block.end());
                forged.insert(forged.end(),
                              ciphertext.begin() + block * BLOCK_SIZE,
                              ciphertext.begin() + block * BLOCK_SIZE + BLOCK_SIZE);

                DWORD status = sendRequestWithRetry(bytesToHex(forged));

                // 404 = valid PKCS#7 padding but bad message  --> oracle says "good padding"
                // 403 = bad PKCS#7 padding                    --> try next guess
                // 200 = valid padding and valid message (rare) --> also good
                if (status == 404 || status == 200) {
                    std::cout << "  [CANDIDATE] Block " << block << " byte " << byte_idx 
                              << " guess=" << guess << " status=" << status << std::endl;
                    // For the last byte, guard against a false positive where a longer
                    // padding sequence (e.g. \x02\x02) accidentally validates.
                    if (byte_idx == BLOCK_SIZE - 1) {
                        // Flip the byte just before and re-check
                        prev_block[byte_idx - 1] ^= 0xFF;
                        std::vector<uint8_t> verify;
                        verify.insert(verify.end(), prev_block.begin(), prev_block.end());
                        verify.insert(verify.end(),
                                      ciphertext.begin() + block * BLOCK_SIZE,
                                      ciphertext.begin() + block * BLOCK_SIZE + BLOCK_SIZE);
                        DWORD vstatus = sendRequestWithRetry(bytesToHex(verify));
                        std::cout << "  [VERIFY] vstatus=" << vstatus << std::endl;
                        if (vstatus == 403) continue; // false positive — keep searching
                    }

                    plaintext_block[byte_idx] = guess;
                    found = true;
                    char ch = (guess >= 32 && guess <= 126) ? (char)guess : '.';
                    std::cout << "[+] Block " << block << " byte " << std::setw(2) << byte_idx
                              << ": '" << ch << "' (0x" << std::hex << std::setw(2)
                              << std::setfill('0') << (int)guess << std::dec
                              << std::setfill(' ') << ")" << std::endl;
                    break;
                }
            }

            if (!found) {
                std::cout << "[-] Failed to find block " << block
                          << " byte " << byte_idx << std::endl;
            }
        }

        // Append decrypted block (strip PKCS#7 padding only on the very last block)
        for (int i = 0; i < BLOCK_SIZE; ++i) {
            decrypted_message += (char)plaintext_block[i];
        }
    }

    // Strip PKCS#7 padding from the end
    if (!decrypted_message.empty()) {
        uint8_t pad = (uint8_t)decrypted_message.back();
        if (pad >= 1 && pad <= BLOCK_SIZE) {
            bool valid_pad = true;
            for (int i = 0; i < pad; ++i) {
                if ((uint8_t)decrypted_message[decrypted_message.size() - 1 - i] != pad) {
                    valid_pad = false; break;
                }
            }
            if (valid_pad) decrypted_message.erase(decrypted_message.size() - pad);
        }
    }

    std::cout << "\n[*] Decrypted Message: " << decrypted_message << std::endl;
    return 0;
}
