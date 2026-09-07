#pragma once

#include <vector>
#include <cstdint>
#include <span>

#include "messages.h"

class RendezvousCodec {
public:
    static std::vector<uint8_t> encode_header(const Header&);
    static Header decode_header(std::span<const uint8_t>);

    static std::vector<uint8_t> encode_endpoint(const Endpoint&);
    static Endpoint decode_endpoint(std::span<const uint8_t>);

    static std::vector<uint8_t> encode_register(const Register&);
    static Register decode_register(std::span<const uint8_t>);

    static std::vector<uint8_t> encode_request(const Request&);
    static Request decode_request(std::span<const uint8_t>);

    static std::vector<uint8_t> encode_notify(const Notify&);
    static Notify decode_notify(std::span<const uint8_t>);
};
