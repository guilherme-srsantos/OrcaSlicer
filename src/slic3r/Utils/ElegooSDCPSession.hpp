#ifndef slic3r_ElegooSDCPSession_hpp_
#define slic3r_ElegooSDCPSession_hpp_

#include <memory>
#include <string>

#include "ElegooLink.hpp"

class WebSocketClient;

namespace Slic3r {

// REA: Persistent SDCP session over the motherboard WebSocket.
//
// Spec (SDCP V3.0.0): the motherboard opens a WebSocket service on port 3030
// after powering on; the client connects to ws://${MainboardIP}:3030/websocket.
// The SDCP "topics" (sdcp/request/..., sdcp/response/..., sdcp/status/...,
// sdcp/attributes/..., sdcp/error/..., sdcp/notice/...) are carried in the
// JSON envelope's "Topic" field — there is no separate MQTT broker on the LAN
// path (the MQTT/Paho stack in Elegoo SatelLite is the WAN/cloud transport).
//
// Heartbeat: the client sends "ping", the motherboard replies "pong".
//
// Note on timeouts: the underlying WebSocketClient::receive() is a blocking
// read without deadline support; wait_response()'s timeout is therefore
// best-effort and relies on the motherboard's periodic status pushes to make
// progress.
class ElegooSDCPSession
{
public:
    // The session reuses ElegooLink's envelope builders and payload parsers.
    explicit ElegooSDCPSession(const ElegooLink& owner);
    ~ElegooSDCPSession();

    ElegooSDCPSession(const ElegooSDCPSession&) = delete;
    ElegooSDCPSession& operator=(const ElegooSDCPSession&) = delete;

    // Connect to ws://${host}:3030/websocket.
    bool connect(const std::string& host, std::string& error_message);
    void disconnect();
    bool is_connected() const { return client_ != nullptr; }

    const std::string& mainboard_id() const { return mainboard_id_; }
    void set_mainboard_id(const std::string& id) { mainboard_id_ = id; }

    // Parse one UDP discovery reply (spec: Device Discovery Description) into
    // the device identity fields. Returns true on a well-formed reply.
    static bool parse_discovery_reply(const std::string& json,
                                      std::string&       mainboard_id,
                                      std::string&       name,
                                      std::string&       machine_name,
                                      std::string&       mainboard_ip,
                                      std::string&       protocol_version,
                                      std::string&       firmware_version);

    // Send an SDCP request on sdcp/request/${MainboardID}; returns the
    // RequestID generated for the envelope (empty on failure).
    std::string send_request(int cmd, const std::string& payload_json);

    // Receive and dispatch messages until a response matching (cmd,
    // request_id) arrives or the timeout elapses. Status / attributes /
    // error / notice messages encountered on the way are consumed into the
    // cache. On success payload_json holds the inner Data.Data JSON.
    bool wait_response(int cmd, const std::string& request_id, unsigned timeout_ms,
                       std::string& payload_json, std::string& error_message);

    // Convenience: send_request + wait_response + Ack check (Ack == 0).
    bool request_ack(int cmd, const std::string& payload_json, unsigned timeout_ms,
                     std::string& error_message);

    // Heartbeat: send "ping" (the motherboard answers "pong", consumed by the
    // receive loop).
    bool ping();

    bool get_last_status(ElegooLink::ElegooSDCPStatus& out) const;
    bool get_last_attributes(ElegooLink::ElegooSDCPAttributes& out) const;

private:
    // Classify and consume one inbound message. Returns true when the message
    // was a response envelope that the caller should inspect further.
    bool dispatch(const std::string& message, std::string& topic,
                  std::string& payload_json, std::string& error_message);

    const ElegooLink&                owner_;
    std::unique_ptr<WebSocketClient> client_;
    std::string                      mainboard_id_;
    ElegooLink::ElegooSDCPStatus     last_status_;
    bool                             has_status_ = false;
    ElegooLink::ElegooSDCPAttributes last_attributes_;
    bool                             has_attributes_ = false;
};

} // namespace Slic3r

#endif // slic3r_ElegooSDCPSession_hpp_
