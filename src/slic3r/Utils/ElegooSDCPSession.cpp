#include "ElegooSDCPSession.hpp"

#include <chrono>
#include <sstream>
#include <boost/log/trivial.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "WebSocketClient.hpp"
#include "slic3r/GUI/GUI.hpp"
#include "slic3r/GUI/I18N.hpp"

namespace pt = boost::property_tree;

namespace Slic3r {

ElegooSDCPSession::ElegooSDCPSession(const ElegooLink& owner) : owner_(owner) {}

ElegooSDCPSession::~ElegooSDCPSession()
{
    disconnect();
}

bool ElegooSDCPSession::connect(const std::string& host, std::string& error_message)
{
    disconnect();
    try {
        client_ = std::make_unique<WebSocketClient>();
        client_->connect(host, std::to_string(ElegooLink::SDCP_WS_PORT), ElegooLink::SDCP_WS_PATH);
        BOOST_LOG_TRIVIAL(info) << "ElegooSDCPSession: connected to ws://" << host << ":"
                                << ElegooLink::SDCP_WS_PORT << ElegooLink::SDCP_WS_PATH;
        return true;
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << "ElegooSDCPSession: connect failed: " << e.what();
        error_message = e.what();
        client_.reset();
        return false;
    }
}

void ElegooSDCPSession::disconnect()
{
    // WebSocketClient closes the connection in its destructor.
    client_.reset();
}

bool ElegooSDCPSession::parse_discovery_reply(const std::string& json,
                                              std::string&       mainboard_id,
                                              std::string&       name,
                                              std::string&       machine_name,
                                              std::string&       mainboard_ip,
                                              std::string&       protocol_version,
                                              std::string&       firmware_version)
{
    try {
        pt::ptree          root;
        std::istringstream is(json);
        pt::read_json(is, root);
        mainboard_id     = root.get<std::string>("Data.MainboardID", "");
        name             = root.get<std::string>("Data.Name", "");
        machine_name     = root.get<std::string>("Data.MachineName", "");
        mainboard_ip     = root.get<std::string>("Data.MainboardIP", "");
        protocol_version = root.get<std::string>("Data.ProtocolVersion", "");
        firmware_version = root.get<std::string>("Data.FirmwareVersion", "");
        return !mainboard_id.empty() && !mainboard_ip.empty();
    } catch (const std::exception&) {
        return false;
    }
}

std::string ElegooSDCPSession::send_request(int cmd, const std::string& payload_json)
{
    if (!client_)
        return {};
    std::string     request_id;
    const std::string envelope = owner_.make_sdcp_request(cmd, payload_json, mainboard_id_, &request_id);
    if (envelope.empty() || request_id.empty())
        return {};
    try {
        client_->send(envelope);
        return request_id;
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << "ElegooSDCPSession: send failed: " << e.what();
        return {};
    }
}

bool ElegooSDCPSession::dispatch(const std::string& message, std::string& topic,
                                 std::string& payload_json, std::string& error_message)
{
    // Heartbeat reply — spec: client sends "ping", motherboard replies "pong".
    if (message == "pong") {
        topic = "pong";
        return false;
    }
    // Classify the envelope by its Topic field, then parse the payload into the
    // matching cache. Response envelopes are left for the caller to correlate.
    try {
        pt::ptree          root;
        std::istringstream is(message);
        pt::read_json(is, root);
        topic = root.get<std::string>("Topic", "");
        auto data = root.get_child_optional("Data");
        if (!data) {
            error_message = "missing Data envelope";
            return false;
        }
        std::ostringstream oss;
        pt::write_json(oss, *data, false);
        payload_json = oss.str();

        if (topic.rfind("sdcp/status/", 0) == 0) {
            if (owner_.parse_sdcp_status(payload_json, last_status_)) {
                has_status_ = true;
                // Track the motherboard id from the payload if not yet known.
                if (mainboard_id_.empty()) {
                    try {
                        pt::ptree pstatus;
                        std::istringstream pis(payload_json);
                        pt::read_json(pis, pstatus);
                        mainboard_id_ = pstatus.get<std::string>("MainboardID", "");
                    } catch (const std::exception&) {}
                }
            }
            return false;
        }
        if (topic.rfind("sdcp/attributes/", 0) == 0) {
            if (owner_.parse_sdcp_attributes(payload_json, last_attributes_)) {
                has_attributes_ = true;
                if (mainboard_id_.empty())
                    mainboard_id_ = last_attributes_.mainboardID;
            }
            return false;
        }
        if (topic.rfind("sdcp/error/", 0) == 0 || topic.rfind("sdcp/notice/", 0) == 0) {
            BOOST_LOG_TRIVIAL(info) << "ElegooSDCPSession: " << topic << " payload: " << payload_json;
            return false;
        }
        // sdcp/response/ and anything else falls through to the caller.
        return topic.rfind("sdcp/response/", 0) == 0;
    } catch (const std::exception& e) {
        error_message = e.what();
        return false;
    }
}

bool ElegooSDCPSession::wait_response(int cmd, const std::string& request_id, unsigned timeout_ms,
                                      std::string& payload_json, std::string& error_message)
{
    if (!client_) {
        error_message = "not connected";
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        std::string message;
        try {
            message = client_->receive();
        } catch (const std::exception& e) {
            error_message = e.what();
            return false;
        }
        if (message.empty())
            continue;
        std::string topic, payload, dispatch_error;
        if (!dispatch(message, topic, payload, dispatch_error)) {
            if (!dispatch_error.empty())
                BOOST_LOG_TRIVIAL(debug) << "ElegooSDCPSession: dropped message (" << dispatch_error << ")";
            continue;
        }
        // Response envelope: match the command and, when provided, the RequestID.
        int  response_cmd = -1;
        try {
            pt::ptree          root;
            std::istringstream is(payload);
            pt::read_json(is, root);
            response_cmd = root.get<int>("Cmd", -1);
            const std::string response_request_id = root.get<std::string>("RequestID", "");
            if (cmd != -1 && response_cmd != cmd)
                continue;
            if (!request_id.empty() && !response_request_id.empty() && response_request_id != request_id)
                continue;
            std::ostringstream oss;
            pt::write_json(oss, root.get_child("Data", pt::ptree()), false);
            payload_json = oss.str();
            return true;
        } catch (const std::exception& e) {
            error_message = e.what();
            return false;
        }
    }
    error_message = "timeout";
    return false;
}

bool ElegooSDCPSession::request_ack(int cmd, const std::string& payload_json, unsigned timeout_ms,
                                    std::string& error_message)
{
    const std::string request_id = send_request(cmd, payload_json);
    if (request_id.empty()) {
        error_message = "send failed";
        return false;
    }
    std::string response_payload;
    if (!wait_response(cmd, request_id, timeout_ms, response_payload, error_message))
        return false;
    try {
        pt::ptree          root;
        std::istringstream is(response_payload);
        pt::read_json(is, root);
        const int ack = root.get<int>("Ack", -1);
        // Spec: Ack == 0 (SDCP_PRINT_CTRL_ACK_OK) means success; other values
        // carry command-specific failure reasons.
        if (ack != 0) {
            error_message = wxString::Format(_L("Error code: %d"), ack).ToUTF8().data();
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        error_message = e.what();
        return false;
    }
}

bool ElegooSDCPSession::ping()
{
    if (!client_)
        return false;
    try {
        client_->send("ping");
        return true;
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << "ElegooSDCPSession: ping failed: " << e.what();
        return false;
    }
}

bool ElegooSDCPSession::get_last_status(ElegooLink::ElegooSDCPStatus& out) const
{
    out = last_status_;
    return has_status_;
}

bool ElegooSDCPSession::get_last_attributes(ElegooLink::ElegooSDCPAttributes& out) const
{
    out = last_attributes_;
    return has_attributes_;
}

} // namespace Slic3r
