#include "hmac_utils.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <openssl/hmac.h>

#include "codec_utils.h"


namespace HMACAuth {
    std::vector<uint8_t> load_secret() {
        const char* value = std::getenv("P2P_SHARED_SECRET");

        if (value == nullptr) throw std::runtime_error("Environment variable P2P_SHARED_SECRET not set");
        if (*value == '\0') throw std::runtime_error("Environment variable can not be of length 0");

        return std::vector<uint8_t>{reinterpret_cast<const uint8_t*>(value), reinterpret_cast<const uint8_t*>(value) + std::strlen(value)};
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& key, std::vector<uint8_t> payload) {
        const auto now = std::chrono::system_clock::now();
        const uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        std::vector<uint8_t> data;
        data.reserve(payload.size() + TIMESTAMP_SIZE + TAG_SIZE);

        data.insert(data.end(), payload.begin(), payload.end());

        for (int i = 7; i >= 0; --i) {
            data.push_back(static_cast<uint8_t>(timestamp >> (i * 8)));
        }

        unsigned char md[TAG_SIZE];
        unsigned int md_len = 0;

        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), md, &md_len);

        data.insert(data.end(), md, md + md_len);

        return data;
    }

    std::optional<std::vector<uint8_t>> verify_and_strip(const std::vector<uint8_t>& key, std::span<const uint8_t> data) {
        if (data.size() < TIMESTAMP_SIZE + TAG_SIZE) return std::nullopt;

        const size_t tag_offset = data.size() - TAG_SIZE;
        const size_t timestamp_offset = data.size() - TAG_SIZE - TIMESTAMP_SIZE;
        const size_t payload_size = timestamp_offset;

        unsigned char md[TAG_SIZE];
        unsigned int md_len = 0;

        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), tag_offset, md, &md_len);

        if (md_len != TAG_SIZE) return std::nullopt;

        if (CRYPTO_memcmp(md, data.data() + tag_offset, TAG_SIZE) != 0) return std::nullopt;

        size_t offset = timestamp_offset;
        const uint64_t sent_at = read_u64(data, offset);

        const auto now = std::chrono::system_clock::now();
        const uint64_t now_secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        const int64_t skew = static_cast<int64_t>(now_secs) - static_cast<int64_t>(sent_at);
        if (std::abs(skew) > MAX_CLOCK_SKEW_SECONDS) return std::nullopt;

        auto payload = data.subspan(0, payload_size);

        return std::vector<uint8_t>(payload.begin(), payload.end());
    }
}
