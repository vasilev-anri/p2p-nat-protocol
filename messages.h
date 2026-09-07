#pragma once
#include <cstdint>


enum class RendezvousMessageType : uint8_t {
    REGISTER  = 0x01,
    KEEPALIVE = 0x02,
    REQUEST   = 0x03,
    NOTIFY    = 0x04,
};

struct Header {
    static constexpr size_t HEADER_SIZE = 9;

    uint64_t node_id;
    RendezvousMessageType type;
};

struct Endpoint {
    static constexpr size_t ENDPOINT_SIZE = 8;

    uint32_t ip;
    uint16_t udp_port;
    uint16_t tcp_port;
};

struct Register {
    Header header;
    Endpoint private_endpoint;
};

struct Request {
    Header header;
    uint64_t target_node_id;
    Endpoint private_endpoint;
};

struct Notify {
    Header header;

    Endpoint public_endpoint;
    Endpoint private_endpoint;
};