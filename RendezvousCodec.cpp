#include "RendezvousCodec.h"

#include "../utils/codec_utils.h"


std::vector<uint8_t> RendezvousCodec::encode_header(const Header& header) {
    std::vector<uint8_t> res{};
    res.reserve(Header::HEADER_SIZE);

    write_u64(header.node_id, res);
    write_u8(static_cast<uint8_t>(header.type), res);

    return res;
}

Header RendezvousCodec::decode_header(std::span<const uint8_t> buf) {
    if (buf.size() < Header::HEADER_SIZE) throw std::runtime_error("Header too short");

    size_t offset = 0;
    Header header{};

    header.node_id = read_u64(buf, offset);
    header.type = static_cast<RendezvousMessageType>(read_u8(buf, offset));

    return header;
}

std::vector<uint8_t> RendezvousCodec::encode_endpoint(const Endpoint& endpoint) {
    std::vector<uint8_t> res{};
    res.reserve(Endpoint::ENDPOINT_SIZE);

    write_u32(endpoint.ip, res);
    write_u16(endpoint.udp_port, res);
    write_u16(endpoint.tcp_port, res);

    return res;
}

Endpoint RendezvousCodec::decode_endpoint(std::span<const uint8_t> buf) {
    if (buf.size() < Endpoint::ENDPOINT_SIZE) throw std::runtime_error("Endpoint too short");

    size_t offset = 0;
    Endpoint endpoint{};

    endpoint.ip = read_u32(buf, offset);
    endpoint.udp_port = read_u16(buf, offset);
    endpoint.tcp_port = read_u16(buf, offset);

    return endpoint;
}

std::vector<uint8_t> RendezvousCodec::encode_register(const Register& msg) {
    std::vector<uint8_t> res{};
    res.reserve(Header::HEADER_SIZE + Endpoint::ENDPOINT_SIZE);

    auto e_header = encode_header(msg.header);
    auto e_endpoint = encode_endpoint(msg.private_endpoint);

    res.insert(res.end(), e_header.begin(), e_header.end());
    res.insert(res.end(), e_endpoint.begin(), e_endpoint.end());

    return res;
}

Register RendezvousCodec::decode_register(std::span<const uint8_t> buf) {
    if (buf.size() < Header::HEADER_SIZE + Endpoint::ENDPOINT_SIZE) throw std::runtime_error("Register message too short");

    Register msg{};

    msg.header = decode_header(buf.subspan(0, Header::HEADER_SIZE));
    msg.private_endpoint = decode_endpoint(buf.subspan(Header::HEADER_SIZE));

    return msg;
}

std::vector<uint8_t> RendezvousCodec::encode_request(const Request& msg) {
    std::vector<uint8_t> res{};
    res.reserve(Header::HEADER_SIZE + 8 + Endpoint::ENDPOINT_SIZE);

    auto e_header = encode_header(msg.header);
    res.insert(res.end(), e_header.begin(), e_header.end());

    write_u64(msg.target_node_id, res);

    auto e_endpoint = encode_endpoint(msg.private_endpoint);
    res.insert(res.end(), e_endpoint.begin(), e_endpoint.end());

    return res;
}

Request RendezvousCodec::decode_request(std::span<const uint8_t> buf) {
    if (buf.size() < Header::HEADER_SIZE + 8 + Endpoint::ENDPOINT_SIZE) throw std::runtime_error("Request message too short");

    Request msg{};

    msg.header = decode_header(buf);

    size_t offset = Header::HEADER_SIZE;

    msg.target_node_id = read_u64(buf, offset);

    msg.private_endpoint = decode_endpoint(buf.subspan(Header::HEADER_SIZE + 8));

    return msg;
}

std::vector<uint8_t> RendezvousCodec::encode_notify(const Notify& msg) {
    std::vector<uint8_t> res{};
    res.reserve(Header::HEADER_SIZE + 2 * Endpoint::ENDPOINT_SIZE);

    auto e_header = encode_header(msg.header);
    res.insert(res.end(), e_header.begin(), e_header.end());

    auto e_pub_endpoint = encode_endpoint(msg.public_endpoint);
    res.insert(res.end(), e_pub_endpoint.begin(), e_pub_endpoint.end());

    auto e_priv_endpoint = encode_endpoint(msg.private_endpoint);
    res.insert(res.end(), e_priv_endpoint.begin(), e_priv_endpoint.end());

    return res;
}

Notify RendezvousCodec::decode_notify(std::span<const uint8_t> buf) {
    if (buf.size() < Header::HEADER_SIZE + 2 * Endpoint::ENDPOINT_SIZE) throw std::runtime_error("Notify message too short");

    Notify msg{};

    msg.header = decode_header(buf);
    msg.public_endpoint = decode_endpoint(buf.subspan(Header::HEADER_SIZE, Endpoint::ENDPOINT_SIZE));
    msg.private_endpoint = decode_endpoint(buf.subspan(Header::HEADER_SIZE + Endpoint::ENDPOINT_SIZE));

    return msg;
}
