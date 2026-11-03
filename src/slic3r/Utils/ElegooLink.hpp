#ifndef slic3r_ElegooLink_hpp_
#define slic3r_ElegooLink_hpp_

#include <boost/optional/optional.hpp>
#include <cstddef>
#include <boost/filesystem/path.hpp>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <wx/string.h>
#include <boost/optional.hpp>
#include <boost/asio/ip/address.hpp>

#include "PrintHost.hpp"
#include "OctoPrint.hpp"

class WebSocketClient;
class ElegooSDCPSession;
namespace boost { template <class T> class optional; }
namespace Slic3r {

class DynamicPrintConfig;
class Http;

class ElegooLink : public OctoPrint
{
public:
    ElegooLink(DynamicPrintConfig *config);
    ~ElegooLink() override = default;
    static std::string get_print_host_webui(DynamicPrintConfig *config);
    const char* get_name() const override;
    virtual bool test(wxString &curl_msg) const override;
    wxString get_test_ok_msg() const override;
    wxString get_test_failed_msg(wxString& msg) const override;
    bool upload(PrintHostUpload upload_data, ProgressFn prorgess_fn, ErrorFn error_fn, InfoFn info_fn) const override;
    std::string get_sn() const override;
    bool has_auto_discovery() const override { return false; }
    bool can_test() const override { return true; }
    PrintHostPostUploadActions get_post_upload_actions() const override;
protected:
#ifdef WIN32
    virtual bool upload_inner_with_resolved_ip(PrintHostUpload upload_data, ProgressFn prorgess_fn, ErrorFn error_fn, InfoFn info_fn, const boost::asio::ip::address& resolved_addr) const override;
#endif
    virtual bool validate_version_text(const boost::optional<std::string> &version_text) const override;
    virtual bool upload_inner_with_host(PrintHostUpload upload_data, ProgressFn prorgess_fn, ErrorFn error_fn, InfoFn info_fn) const override;

#ifdef WIN32
    virtual bool test_with_resolved_ip(wxString& curl_msg) const override;
    bool elegoo_test_with_resolved_ip(wxString& curl_msg) const;
#endif
private:
    // The persistent WebSocket session reuses this class's envelope builders
    // and payload parsers.
    friend class ElegooSDCPSession;

    bool elegoo_test(wxString& curl_msg) const;
    bool elegoo_cc2_test(wxString& curl_msg) const;
    bool print(WebSocketClient&  client,
               std::string       timeLapse,
               std::string       heatedBedLeveling,
               std::string       bedType,
               const std::string filename, ErrorFn error_fn) const;
    bool checkResult(WebSocketClient&  client,
               ErrorFn           error_fn) const;

    // --- REA: SDCP protocol extensions (from Elegoo SatelLite reverse engineering,
    // cross-validated against the official SDCP V3.0.0 spec) ---
    // Official SDCP V3.0.0 command set. Print control commands (128-133) were
    // corrected from the official spec; earlier RE-derived IDs 2-26 were
    // speculative and are superseded by these.
    enum ElegooSDCPCommand {
        SDCP_GET_STATUS              = 0,   // Request status refresh (Cmd 0)
        SDCP_GET_PROPERTIES          = 1,   // Request attribute refresh (Cmd 1)
        SDCP_START_PRINT             = 128, // Start printing (Cmd 128)
        SDCP_PAUSE_PRINT             = 129, // Pause printing (Cmd 129)
        SDCP_STOP_PRINT              = 130, // Stop printing (Cmd 130)
        SDCP_CONTINUE_PRINT          = 131, // Continue printing (Cmd 131)
        SDCP_STOP_FEEDING            = 132, // Stop feeding material (Cmd 132)
        SDCP_SKIP_PREHEATING         = 133, // Skip preheating (Cmd 133)
        SDCP_CHANGE_PRINTER_NAME     = 192, // Change printer name (Cmd 192)
        SDCP_GET_FILE_LIST           = 258, // Retrieve file list (Cmd 258)
        SDCP_DELETE_FILES            = 259, // Batch delete files (Cmd 259)
        SDCP_GET_HISTORY_TASKS       = 320, // Retrieve historical tasks (Cmd 320)
        SDCP_GET_TASK_DETAILS        = 321, // Retrieve task details (Cmd 321)
        SDCP_VIDEO_STREAM_ENABLE     = 386, // Enable/disable video stream (Cmd 386)
        SDCP_TIMELAPSE_ENABLE        = 387, // Enable/disable time-lapse (Cmd 387)
        SDCP_TERMINATE_FILE_TRANSFER = 255, // Terminate file transfer (Cmd 255)
    };

    // Official SDCP machine status (sdcp_machine_status_t)
    enum ElegooSDCPMachineStatus {
        SDCP_MACHINE_STATUS_IDLE = 0,
        SDCP_MACHINE_STATUS_PRINTING = 1,
        SDCP_MACHINE_STATUS_FILE_TRANSFERRING = 2,
        SDCP_MACHINE_STATUS_EXPOSURE_TESTING = 3,
        SDCP_MACHINE_STATUS_DEVICES_TESTING = 4,
    };

    // Official SDCP print sub-status (sdcp_print_status_t)
    enum ElegooSDCPPrintStatus {
        SDCP_PRINT_STATUS_IDLE = 0,
        SDCP_PRINT_STATUS_HOMING = 1,
        SDCP_PRINT_STATUS_DROPPING = 2,
        SDCP_PRINT_STATUS_EXPOSURING = 3,
        SDCP_PRINT_STATUS_LIFTING = 4,
        SDCP_PRINT_STATUS_PAUSING = 5,
        SDCP_PRINT_STATUS_PAUSED = 6,
        SDCP_PRINT_STATUS_STOPPING = 7,
        SDCP_PRINT_STATUS_STOPPED = 8,
        SDCP_PRINT_STATUS_COMPLETE = 9,
        SDCP_PRINT_STATUS_FILE_CHECKING = 10,
    };

    // Official SDCP print error (sdcp_print_error_t)
    enum ElegooSDCPPrintError {
        SDCP_PRINT_ERROR_NONE = 0,
        SDCP_PRINT_ERROR_CHECK = 1,
        SDCP_PRINT_ERROR_FILEIO = 2,
        SDCP_PRINT_ERROR_INVALID_RESOLUTION = 3,
        SDCP_PRINT_ERROR_UNKNOWN_FORMAT = 4,
        SDCP_PRINT_ERROR_UNKNOWN_MODEL = 5,
    };

    // Official SDCP error cause (sdcp_print_cause_t) — full set from spec
    enum ElegooSDCPPrintCause {
        SDCP_PRINT_CAUSE_OK = 0,
        SDCP_PRINT_CAUSE_TEMP_ERROR = 1,
        SDCP_PRINT_CAUSE_CALIBRATE_FAILED = 2,
        SDCP_PRINT_CAUSE_RESIN_LACK = 3,
        SDCP_PRINT_CAUSE_RESIN_OVER = 4,
        SDCP_PRINT_CAUSE_PROBE_FAIL = 5,
        SDCP_PRINT_CAUSE_FOREIGN_BODY = 6,
        SDCP_PRINT_CAUSE_LEVEL_FAILED = 7,
        SDCP_PRINT_CAUSE_RELEASE_FAILED = 8,
        SDCP_PRINT_CAUSE_SG_OFFLINE = 9,
        SDCP_PRINT_CAUSE_LCD_DET_FAILED = 10,
        SDCP_PRINT_CAUSE_RELEASE_OVERCOUNT = 11,
        SDCP_PRINT_CAUSE_UDISK_REMOVE = 12,
        SDCP_PRINT_CAUSE_HOME_FAILED_X = 13,
        SDCP_PRINT_CAUSE_HOME_FAILED_Z = 14,
        SDCP_PRINT_CAUSE_RESIN_ABNORMAL_HIGH = 15,
        SDCP_PRINT_CAUSE_RESIN_ABNORMAL_LOW = 16,
        SDCP_PRINT_CAUSE_HOME_FAILED = 17,
        SDCP_PRINT_CAUSE_PLAT_FAILED = 18,
        SDCP_PRINT_CAUSE_ERROR = 19,
        SDCP_PRINT_CAUSE_MOVE_ABNORMAL = 20,
        SDCP_PRINT_CAUSE_AIC_MODEL_NONE = 21,
        SDCP_PRINT_CAUSE_AIC_MODEL_WARP = 22,
        SDCP_PRINT_CAUSE_HOME_FAILED_Y = 23,
        SDCP_PRINT_CAUSE_FILE_ERROR = 24,
        SDCP_PRINT_CAUSE_CAMERA_ERROR = 25,
        SDCP_PRINT_CAUSE_NETWORK_ERROR = 26,
        SDCP_PRINT_CAUSE_SERVER_CONNECT_FAILED = 27,
        SDCP_PRINT_CAUSE_DISCONNECT_APP = 28,
        SDCP_PRINT_CAUSE_CHECK_AUTO_RESIN_FEEDER = 29,
        SDCP_PRINT_CAUSE_CONTAINER_RESIN_LOW = 30,
        SDCP_PRINT_CAUSE_BOTTLE_DISCONNECT = 31,
        SDCP_PRINT_CAUSE_FEED_TIMEOUT = 32,
        SDCP_PRINT_CAUSE_TANK_TEMP_SENSOR_OFFLINE = 33,
        SDCP_PRINT_CAUSE_TANK_TEMP_SENSOR_ERRO = 34,
    };

    // Official SDCP "From" field (sdcp_from_t)
    enum ElegooSDCPFrom {
        SDCP_FROM_PC = 0,        // Local PC software (LAN)
        SDCP_FROM_WEB_PC = 1,    // PC software via WEB
        SDCP_FROM_WEB = 2,       // Web client
        SDCP_FROM_APP = 3,       // APP
        SDCP_FROM_SERVER = 4,    // Server
    };

    // Official SDCP file transfer ack (sdcp_file_transfer_ack_t)
    enum ElegooSDCPFileTransferAck {
        SDCP_FILE_TRANSFER_ACK_SUCCESS = 0,
        SDCP_FILE_TRANSFER_ACK_NOT_TRANSFER = 1,
        SDCP_FILE_TRANSFER_ACK_CHECKING = 2,
        SDCP_FILE_TRANSFER_ACK_NOT_FOUND = 3,
    };

    // --- REA: SDCP status/attribute models, spec-accurate (SDCP V3.0.0) ---

    // PrintInfo sub-object from the status payload (spec: Status Information)
    struct ElegooSDCPPrintInfo {
        int          status = 0;        // PrintInfo.Status — print sub-status (sdcp_print_status_t)
        int          currentLayer = 0;  // PrintInfo.CurrentLayer
        int          totalLayer = 0;    // PrintInfo.TotalLayer
        long         currentTicks = 0;  // PrintInfo.CurrentTicks (ms)
        long         totalTicks = 0;    // PrintInfo.TotalTicks (ms)
        std::string  filename;          // PrintInfo.Filename
        int          errorNumber = 0;   // PrintInfo.ErrorNumber (sdcp_print_error_t)
        std::string  taskId;            // PrintInfo.TaskId

        double progress_percent() const { return totalTicks > 0 ? (100.0 * currentTicks / totalTicks) : 0.0; }
    };

    // Full SDCP status model (spec: "Status Information" payload, Status object)
    struct ElegooSDCPStatus {
        std::vector<int>    currentStatus;      // Status.CurrentStatus — machine statuses (sdcp_machine_status_t)
        int                 previousStatus = 0; // Status.PreviousStatus
        long                printScreen = 0;    // Status.PrintScreen — total exposure screen usage (s)
        long                releaseFilm = 0;    // Status.ReleaseFilm — total release film usage count
        double              tempOfUVLED = 0;    // Status.TempOfUVLED (℃)
        int                 timeLapseStatus = 0;// Status.TimeLapseStatus — 0: Off, 1: On
        double              tempOfBox = 0;      // Status.TempOfBox (℃)
        double              tempTargetBox = 0;  // Status.TempTargetBox (℃)
        ElegooSDCPPrintInfo printInfo;          // Status.PrintInfo

        bool has_current_status(int code) const { return std::find(currentStatus.begin(), currentStatus.end(), code) != currentStatus.end(); }
        bool is_printing() const { return has_current_status(SDCP_MACHINE_STATUS_PRINTING); }
        bool is_idle() const { return has_current_status(SDCP_MACHINE_STATUS_IDLE); }
    };

    // DevicesStatus sub-object from the attributes payload (device self-check)
    struct ElegooSDCPDevicesStatus {
        int tempSensorStatusOfUVLED = 0;  // 0: Disconnected, 1: Normal, 2: Abnormal
        int lcdStatus = 0;                // 0: Disconnected, 1: Connected
        int sgStatus = 0;                 // 0: Disconnected, 1: Normal, 2: Calibration Failed
        int zMotorStatus = 0;             // 0: Disconnected, 1: Connected
        int rotateMotorStatus = 0;        // 0: Disconnected, 1: Connected
        int releaseFilmState = 0;         // 0: Abnormal, 1: Normal
        int xMotorStatus = 0;             // 0: Disconnected, 1: Connected
    };

    // Full SDCP attributes model (spec: "Attribute Information" payload, Attributes object)
    struct ElegooSDCPAttributes {
        std::string  name;                     // Attributes.Name
        std::string  machineName;              // Attributes.MachineName
        std::string  brandName;                // Attributes.BrandName
        std::string  protocolVersion;          // Attributes.ProtocolVersion
        std::string  firmwareVersion;          // Attributes.FirmwareVersion
        std::string  resolution;               // Attributes.Resolution (e.g. "7680x4320")
        std::string  xyzSize;                  // Attributes.XYZsize (e.g. "210x140x100" mm)
        std::string  mainboardIP;              // Attributes.MainboardIP
        std::string  mainboardID;              // Attributes.MainboardID
        int          numberOfVideoStreamConnected = 0;
        int          maximumVideoStreamAllowed = 0;
        std::string  networkStatus;            // 'wlan' | 'eth'
        int          usbDiskStatus = 0;        // 0: Disconnected, 1: Connected
        std::vector<std::string> capabilities;   // FILE_TRANSFER, PRINT_CONTROL, VIDEO_STREAM
        std::vector<std::string> supportFileType; // e.g. "CTB"
        ElegooSDCPDevicesStatus devicesStatus; // DevicesStatus
        long         releaseFilmMax = 0;       // Maximum release film uses
        double       tempOfUVLEDMax = 0;       // Maximum UVLED operating temp (℃)
        int          cameraStatus = 0;         // 0: Disconnected, 1: Connected
        long         remainingMemory = 0;      // Remaining storage (bit)
        double       tlpNoCapPos = 0;          // Model height threshold for no TLP (mm)
        double       tlpStartCapPos = 0;       // Print height where TLP begins (mm)
        int          tlpInterLayers = 0;       // TLP shooting interval layers

        bool supports(const std::string& capability) const {
            return std::find(capabilities.begin(), capabilities.end(), capability) != capabilities.end();
        }
    };

    // --- REA: SDCP network constants (spec-accurate, SDCP V3.0.0) ---
    // The motherboard starts a WebSocket service on port 3030 after powering on.
    // The client broadcasts "M99999" via UDP on port 3000 to discover devices.
    static constexpr unsigned short SDCP_UDP_DISCOVERY_PORT = 3000;
    static constexpr unsigned short SDCP_WS_PORT            = 3030;
    static constexpr const char*    SDCP_WS_PATH            = "/websocket";
    static constexpr const char*    SDCP_DISCOVERY_MAGIC    = "M99999";

    // Build a canonical SDCP JSON envelope. MainboardID can be empty for the legacy
    // WebSocket bridge (the bridge fills it in) but must be filled for direct MQTT.
    // When request_id_out is provided it receives the generated RequestID so the
    // caller can correlate the matching sdcp/response message.
    std::string make_sdcp_request(int cmd, const std::string& payload_json,
                                  const std::string& mainboard_id = "",
                                  std::string* request_id_out = nullptr) const;
    // Parse a canonical SDCP response envelope. Returns true if a valid envelope was
    // found and `cmd` matches the requested command (or -1 to accept any).
    bool parse_sdcp_response(const std::string& json, int cmd,
                             std::string& payload_json, std::string& error_message) const;
    // Parse the full SDCP status payload into the structured model (spec: Status Information).
    bool parse_sdcp_status(const std::string& payload_json, ElegooSDCPStatus& out) const;
    // Parse the full SDCP attributes payload into the structured model (spec: Attribute Information).
    bool parse_sdcp_attributes(const std::string& payload_json, ElegooSDCPAttributes& out) const;

    // --- REA: SDCP print control over the WebSocket bridge (spec commands 129-131) ---
    bool sdcp_print_control(WebSocketClient& client, int cmd, ErrorFn error_fn) const;
    bool sdcp_pause_print(WebSocketClient& client, ErrorFn error_fn) const;
    bool sdcp_stop_print(WebSocketClient& client, ErrorFn error_fn) const;
    bool sdcp_continue_print(WebSocketClient& client, ErrorFn error_fn) const;

    // --- REA: UDP discovery (spec: broadcast "M99999" to UDP port 3000) ---
    // Sends the discovery broadcast and collects replies for up to timeout_ms.
    // Returns true if at least one device replied; reply JSON bodies are returned
    // in `replies` (one per responding motherboard).
    bool discover_devices(std::vector<std::string>& replies, unsigned timeout_ms = 1500) const;

    // --- REA: HTTP LAN REST endpoints (from Elegoo SatelLite EleNetManager.dll) ---
    // These are the fallback/control path used by Elegoo SatelLite in addition to MQTT.
    bool http_request_json(const std::string& path, const std::string& body,
                           std::string& out_body, wxString& msg) const;
    bool http_get_file_list(std::string& body, wxString& msg) const;
    bool http_get_file_list_internal(std::string& body, wxString& msg) const;
    bool http_get_status(std::string& body, wxString& msg) const;
    bool http_print_control(const std::string& action, wxString& msg) const; // action = start|stop|pause|quit|force|finish
    bool http_print_copy_stop(wxString& msg) const;
    bool http_get_live_camera(std::string& body, wxString& msg) const;
    bool http_get_printer_name(std::string& body, wxString& msg) const;
    bool http_get_printer_profile(std::string& body, wxString& msg) const;
    bool http_get_timelapse(std::string& body, wxString& msg) const;
    bool http_get_timelapse_list(std::string& body, wxString& msg) const;

    bool loopUpload(std::string url, PrintHostUpload upload_data,
                    ProgressFn        prorgess_fn,
                    ErrorFn           error_fn,
                    InfoFn            info_fn) const;
    bool loopUploadCC2(std::string url,
                       const std::string& host_header,
                       PrintHostUpload    upload_data,
                       ProgressFn         prorgess_fn,
                       ErrorFn            error_fn,
                       InfoFn             info_fn) const;

    bool uploadPart(Http &http,
                    std::string       md5,
                    std::string       uuid,
                    std::string       path,
                    std::string       filename,
                    size_t            filesize,
                    size_t            offset,
                    size_t            length,
                    ProgressFn        prorgess_fn,
                    ErrorFn           error_fn,
                    InfoFn            info_fn) const;
    bool uploadPartCC2(Http&                           http,
                       const std::string&             host_header,
                       const std::string&             token,
                       const std::string&             md5,
                       const boost::filesystem::path& path,
                       const std::string&             filename,
                       size_t                         filesize,
                       size_t                         offset,
                       size_t                         length,
                       ProgressFn                     prorgess_fn,
                       ErrorFn                        error_fn) const;

    std::string cc2_token() const;
    std::string make_cc2_info_url() const;
    std::string make_cc2_upload_url() const;
#ifdef WIN32
    bool elegoo_cc2_test_with_resolved_ip(wxString& curl_msg) const;
#endif

    std::string m_printerModel;
};
}

#endif
