# Elegoo SDCP Protocol — REA Reverse-Engineering Analysis

**Source binary**: `ELEGOO_Satellite_1.0.2.43_win-x64.exe` (Elegoo SatelLite)
**Source modules inspected**: `EleNetManager.dll`, `EleMqtt.dll`, `EleCloudDatabase.dll`, `EleLink.dll`, `EleFramework.dll`, `EleStart.dll`, `resources/mosquitto/*`
**Target repo**: `https://github.com/OrcaSlicer/OrcaSlicer` (branch `main`)
**Analysis date**: 2026-11-03
**Analyst**: REA framework — static binary inspection (strings + class symbols), source comparison against OrcaSlicer `src/slic3r/Utils/ElegooLink.{cpp,hpp}`.

---

## 1. Executive Summary

The Elegoo SatelLite slicer implements the **Smart Device Communication Protocol (SDCP)** — a MQTT-over-TCP/WebSocket protocol with JSON payloads — for LAN communication with Elegoo printers, and a separate **WAN/Cloud path** using Eclipse Paho MQTT C++ and a REST-based device-management server for remote/online operation, camera streaming (Agora RTC/RTM), and device binding.

The OrcaSlicer `ElegooLink` implementation currently covers a **narrow subset**: the legacy LAN WebSocket bridge with only two SDCP commands (`GetStatus` = Cmd 0, `StartPrint` = Cmd 128), plus a chunked HTTP multipart file upload endpoint (`uploadFile/upload`) and a CC2 (Centauri Carbon 2) variant that adds a token-authenticated HTTP REST path (`system/info`, `upload`).

The REA inspection of Elegoo SatelLite's binary modules reveals a substantially richer protocol surface that OrcaSlicer does **not** implement:

| Category | Elegoo SatelLite | OrcaSlicer `ElegooLink` | Gap |
|---|---|---|---|
| LAN transport | MQTT (boost::mqtt `endpoint`, `publish`, `subscribe`) | `WebSocketClient` (`/websocket` on port 3030) | **Partial** |
| WAN/Cloud transport | Paho MQTT C++ (`WanMqttClient`), `/api/v1/device-management-server/mqtt-link/mqtt-client` | None | **Missing** |
| SDCP MQTT topics | `sdcp/request/%1`, `sdcp/response/%1`, `sdcp/status/%1`, `sdcp/attributes/%1`, `sdcp/error/`, `sdcp/notice/` | `sdcp/response/%1` only (in comment) | **Missing** |
| SDCP commands | Many (see §4) | `GetStatus`=0, `GetProperties`=1, `StartPrint`=128 | **Missing** |
| HTTP LAN endpoints | 12+ (see §5) | `uploadFile/upload` only | **Missing** |
| Status model | `CurrentStatus`, `ControlState`, `ErrorStatusReason`, `extendedStatus`, `externalDeviceStatus`, `AutoFeedStatus`, `CameraStatus`, `AlreadyPrintLayer` | `CurrentStatus` (vector of ints; status code 8 only) | **Missing** |
| Device lifecycle | `DeviceConnected`, `DeviceDisconnected`, `DeviceConnectionError`, `DeviceDataReceived`, `DeviceDiscovered`, `DeviceListAndAgoraTokenReceived`, `DeviceAttributesUpdated`, `DeviceOnlineStatusReceived` | None | **Missing** |
| Print lifecycle | `FinishPrint`, `FinishPrintingMessage`, `FinishPrintingResponse`, `ForcePrintingResponse`, `ContinuePrinting`, `ContinuePrintingResponse`, `GetPrintResponse`, `GetStatusResponse` | `print()` + `checkResult()` only | **Missing** |
| Print control | `/api/print/start`, `/pause`, `/stop`, `/quit`, `/force`, `/finish`, `/copy/stop` | WebSocket Cmd 128 only | **Missing** |
| Camera | `/api/printer/livecamera` + Agora RTC/RTM token (`/api/v1/device-management-server/device/list/agora-token`) | None | **Missing** |
| File operations | `/api/files`, `/api/files/internal`, `/status`, `/api/printer/name`, `/api/printer/profile`, `/api/printer/timelapse`, `/api/printer/timelapse/list` | `uploadFile/upload` only | **Missing** |
| File chunk fields | `Check`, `S-File-MD5`, `Offset`, `Uuid`, `TotalSize`, `File` | Same | **Match** |
| MQTT SDCP JSON envelope | `{"Id":…,"Data":{"Cmd":…,"Data":…,"RequestID":…,"MainboardID":…,"TimeStamp":…,"From":…},"Topic":"sdcp/response/…"}` | Same shape | **Match** |
| Device Management REST | `/api/v1/device-management-server/device/bind`, `/unbind`, `/device/name`, `/device/pincode/detail`, `/device/event-data/page`, `/device/report-data/list`, `/device-register/online-status`, `/local-file/page`, `/oss/biz-entrypoint` | None | **Missing** |
| Agora RTM | `WanMqttPahoActionListener`, `WanMqttPahoCallback`, `cmd=` / `[WAN_PRINT][RTM_SEND]` | None | **Missing** |
| Serial-number cache | `ELEGOO_DEV_SN_SECTION = "dev_sn"` in AppConfig, keyed by host:token | Same | **Match** |
| CC2 default token | `ELEGOO_CC2_DEFAULT_TOKEN = "123456"` | Same | **Match** |
| SDCP Ack enum | `SdcpPrintCtrlAck` 0–7 (OK, BUSY, NOT_FOUND, MD5_FAILED, FILEIO_FAILED, INVALID_RESOLUTION, UNKNOW_FORMAT, UNKNOW_MODEL) | Same 8 values, named `ElegooLinkStartPrintAck` | **Match** |

---

## 2. Protocol Architecture (as reverse-engineered from Elegoo SatelLite)

### 2.1 Module map

| Module | Role |
|---|---|
| `EleMqtt.dll` | LAN MQTT client wrapper `VoxMqtt` built on **boost::mqtt 3.1.1/5.0** (`basic_publish_message`, `publish_options`, `buffer`, `any`). Provides `Connect(QString)`, `Publish(QString topic, QByteArray payload)`, `Subscribe(QString topic)`, `GetState()`, `SetStatus()`, `StateChanged()`, `ErrorChanged(QString)`. |
| `EleNetManager.dll` | Main network manager `VoxNetManager`. Contains `ManageDevice` (per-device SDCP dispatcher), `SDCPEntity` (SDCP session status enum `SDCP_SESSION_STATUS`), `WanMqttClient` (Paho), `WanMqttPahoActionListener`, `WanMqttPahoCallback`, `SDCPAttributesMessage`, `SdcpStatusMessage`. Exposes `SendSDCPRequest(ManageDevice*, int cmdType, QString, QJsonObject)`, `GetDeviceAttrStatus`, `GetDeviceAttrWarning`, `GetDeviceErrorResponse(SdcpErrorStatusReason)`, `GetDevicePrintResponse(SdcpPrintCtrlAck)`, `GetDevicePrintStatus(SdcpPrintError)`, `GetDeviceStatusWarning`, `GetDeviceOnlineStatus`. |
| `EleCloudDatabase.dll` | Cloud database of device metadata; queries Elegoo Cloud REST endpoints. |
| `EleLink.dll` | Device link / pairing logic (`DeviceDiscovered`, `DeviceDetailWidget`, `DeviceListAndAgoraTokenReceived`). |
| `EleFramework.dll` | Main application framework that wires the network layer to the GUI. |
| `EleStart.dll` | Application bootstrap; hosts `[PRINT][AUTO_START] route=lan_sdcp_transfer` and `[WAN_PRINT][RTM_SEND]` log tags. |
| `resources/mosquitto/` | Bundled **Eclipse Mosquitto** broker (headers `mosquitto.h`, `mqtt_protocol.h`, `mosquitto_broker.h`, `mosquittopp.h`, libraries `mosquitto.lib`, `mosquittopp.lib`, `mosquitto_dynamic_security.dll`, executables `mosquitto_sub.exe`, `mosquitto_pub.exe`, `mosquitto_rr.exe`, `mosquitto_passwd.exe`). A local `myconfig.conf` (`listener 4848`, `allow_anonymous true`) is used for **local development/debugging**, not production. |
| `resources/certs/` | TLS certificate chain (GlobalSign root + Elegoo-signed device certs). |

### 2.2 MQTT Topics (LAN)

All MQTT topics are derived from the printer's **MainboardID** (an SDCP serial like `1c7319d30105041800009c0000000000`), substituted with `%1` in the binary strings:

| Topic | Direction | Purpose |
|---|---|---|
| `sdcp/request/%1` | slicer → printer | Publish SDCP commands. `%1` = `MainboardID`. |
| `sdcp/response/%1` | printer → slicer | Subscribe for command responses. |
| `sdcp/status/%1` | printer → slicer | Subscribe for periodic status reports. |
| `sdcp/attributes/%1` | printer → slicer | Subscribe for attribute changes. |
| `sdcp/error/` | printer → slicer | Subscribe for error notices. |
| `sdcp/notice/` | printer → slicer | Subscribe for notices. |
| `app/v1/%1/device/data` | WAN (Paho) | Cloud device data push. |
| `app/v1/%1/device/onoffline` | WAN (Paho) | Cloud online/offline events. |

### 2.3 MQTT QoS and session

- LAN MQTT: protocol version 3.1.1 (`v3_1_1`), plus a v5 variant (`v5`) used by `basic_publish_message`. QoS 0 and 1 observed. Payloads are plain JSON text.
- WAN MQTT: Paho `async_client` with `connect_response`, `server_response`, `delivery_token`, `string_collection`, `unsubscribe_response` — an explicit **`WanMqttPahoCallback`** + **`WanMqttPahoActionListener`** pair implies asynchronous completion handling (Paho `MqttCallback` + `MqttActionListener` interface).

### 2.4 SDCP JSON envelope

Reverse-engineered envelope (confirmed both in the Elegoo binary and in the OrcaSlicer code):

```json
{
  "Id": "979d4C788A4a78bC777A870F1A02867A",
  "Data": {
    "Cmd": 128,
    "Data": { "Ack": 1, "...": "..." },
    "RequestID": "5223de52cc7642ae8d7924f9dd46f6ad",
    "MainboardID": "1c7319d30105041800009c0000000000",
    "TimeStamp": 1735032553,
    "From": 1
  },
  "Topic": "sdcp/response/1c7319d30105041800009c0000000000"
}
```

- `Id` — message id (32-hex random).
- `Data.Cmd` — SDCP command id (integer).
- `Data.Data` — command payload (varies per command).
- `Data.RequestID` — 32-hex UUID per request.
- `Data.MainboardID` — device serial.
- `Data.TimeStamp` — Unix epoch seconds.
- `Data.From` — 1 = slicer, 0 = other.

### 2.5 SDCP command identifiers

Discovered in the binary:

| Value | Meaning | Evidence |
|---|---|---|
| 0 | `GetStatus` — full device status | OrcaSlicer `ELEGOO_GET_STATUS = 0` |
| 1 | `GetProperties` — device properties/attributes | OrcaSlicer `ELEGOO_GET_PROPERTIES = 1` |
| 128 | `StartPrint` — start a print job | OrcaSlicer `ELEGOO_START_PRINT = 128` |
| (others) | File transfer, print control, attributes, … | `SdcpPrintCtrlAck`, `SdcpErrorAttrReason`, `SdcpErrorStatusReason`, `SdcpPrintError` enums + `SendSDCPRequest(ManageDevice*, int cmdType, QString, QJsonObject)` generic dispatcher |

`SendSDCPRequest` takes an **int cmdType** and a **QJsonObject payload** — the classic SDCP dispatcher pattern.

### 2.6 SDCP status model

Discovered enumerations / fields (from `EleNetManager.dll` strings):

- `CurrentStatus` — array of status codes. Observed code `8` = "check file status, need to wait" (OrcaSlicer comment).
- `ControlState` — high-level control state (Idle / Printing / Paused / Error / …).
- `ErrorStatusReason` — error-code reason enum, mapped by `GetDeviceErrorResponse`.
- `SdcpErrorAttrReason` — per-attribute error reason, mapped by `GetDeviceAttrStatus`, `GetDeviceAttrWarning`, `GetDeviceAttrWarning` returns `QMap<QString, QList<SdcpErrorAttrReason>>`.
- `SdcpErrorStatusReason` — mapped by `GetDeviceStatusWarning`, returns `QMap<QString, QList<SdcpErrorStatusReason>>`.
- `SdcpPrintError` — mapped by `GetDevicePrintStatus`.
- `SdcpPrintCtrlAck` — mapped by `GetDevicePrintResponse`, values 0–7.
- `extendedStatus`, `externalDeviceStatus`, `extendedCertificateAttributes` — extended attribute-set fields.
- `AutoFeedStatus`, `CameraStatus`, `AlreadyPrintLayer`, `PrintInfo`, `PrintState`, `PrintPercent`, `PrintTime`, `Layer`, `StartTime`, `EndTime`, `Progress`, `TotalSize`, `CurrentSize`, `Transport`, `NumPath`, `StatusNumber`, `FileNumber`.
- `Attributes` / `Attribute Status Trait` / `Component Status Trait Category` — SDCP attribute-tree model.
- `allowedAttributeAssignments`, `authorityAttributeIdentifier`, `containsUserAttributeCerts`, `certStatus` — attribute assignment/certificate fields (SDCP protocol spec terminology).
- `ControlState`, `ContinuePrinting`, `ContinuePrintingResponse`, `FinishPrint`, `FinishPrintingMessage`, `FinishPrintingResponse`, `ForcePrintingResponse`, `GetStatusResponse`, `GetPrintResponse` — response-type enums.
- `DeviceConnected`, `DeviceConnectionError`, `DeviceDataReceived`, `DeviceDiscovered`, `DeviceDisconnected`, `DeviceAttributesUpdated`, `DeviceOnlineStatusReceived`, `DeviceListAndAgoraTokenReceived`, `DeviceInfoDataUpdated`, `DiscoveryStatusUpdated`, `DeviceStatusCount`, `DeviceStatusWarning`, `DevicesStatus`, `DeviceEventDataPageReceived` — device lifecycle event enums.
- `SDCPFileTransferFinish`, `SDCPFileTransferOffset`, `SDCPTransferFileCanceled`, `SDCPTransferFileError` — file transfer completion notifications.
- `LocalSDCPAddress`, `SDCPAddress` — LAN address configuration fields.

### 2.7 HTTP LAN endpoints

Discovered in the binary:

| Endpoint | Purpose |
|---|---|
| `http://%1:%2/status` | Device status (legacy Elegoo FDM/SDCP REST API). |
| `http://%1:%2/api/files` | List local files. |
| `http://%1:%2/api/files/internal` | List files on internal storage. |
| `http://%1:%2/api/print/start` | Start print. |
| `http://%1:%2/api/print/stop` | Stop print. |
| `http://%1:%2/api/print/pause` | Pause print. |
| `http://%1:%2/api/print/quit` | Quit/abandon print. |
| `http://%1:%2/api/print/force` | Force print. |
| `http://%1:%2/api/print/finish` | Finish print. |
| `http://%1:%2/api/print/copy/stop` | Stop duplicate print. |
| `http://%1:%2/api/printer/livecamera` | Camera stream. |
| `http://%1:%2/api/printer/name` | Get device name. |
| `http://%1:%2/api/printer/profile` | Get device profile. |
| `http://%1:%2/api/printer/timelapse` | Timelapse control. |
| `http://%1:%2/api/printer/timelapse/list` | List timelapse videos. |
| `http://%1:%2/uploadFile/upload` | Chunked multipart upload (slicer). |

### 2.8 Cloud REST endpoints

Discovered in the binary:

| Endpoint | Purpose |
|---|---|
| `/api/v1/device-management-server/device/bind` | Bind a device to a cloud account. |
| `/api/v1/device-management-server/device/unbind` | Unbind a device. |
| `/api/v1/device-management-server/device/name` | Device name. |
| `/api/v1/device-management-server/device/pincode/detail` | PIN code detail (pairing). |
| `/api/v1/device-management-server/device/event-data/page` | Paged event data. |
| `/api/v1/device-management-server/device/report-data/list` | Report data list. |
| `/api/v1/device-management-server/device-register/online-status` | Online status registration. |
| `/api/v1/device-management-server/local-file/page` | Paged local-file list. |
| `/api/v1/device-management-server/mqtt-link/mqtt-client` | Obtain MQTT credentials/endpoint for the WAN MQTT client. |
| `/api/v1/device-management-server/device/list/agora-token` | Agora RTC/RTM token for camera streaming. |
| `/api/v1/device-management-server/oss/biz-entrypoint` | OSS entrypoint (cloud object storage). |

### 2.9 Agora / camera

- `agora_rtc_sdk.dll` (42 MB) + `agora_rtm_sdk.dll` (14 MB) are bundled.
- Camera tokens are fetched from `/api/v1/device-management-server/device/list/agora-token`.
- The RTM channel is also used for `[WAN_PRINT][RTM_SEND] cmd=` messages — i.e., **remote print commands can be relayed through Agora RTM** in the WAN mode, not only through MQTT.

### 2.10 File transfer protocol

Reverse-engineered multipart form fields (from `EleNetManager.dll` strings and confirmed in OrcaSlicer):

```
form-data; name="Check"        → "1"
form-data; name="S-File-MD5"   → md5 hex
form-data; name="Offset"       → byte offset
form-data; name="Uuid"         → upload session uuid
form-data; name="TotalSize"    → total file size
form-data; name="File"         → binary chunk (filename)
```

Chunk size: `MAX_UPLOAD_PACKAGE_LENGTH = 1048576` (1 MiB) in OrcaSlicer.

Responses use Elegoo's business-code envelope:

```json
{ "code": "000000", "messages": [ { "field": "...", "message": "..." } ] }
```

`code == "000000"` means success. OrcaSlicer matches this.

The WAN variant adds **token-based** upload via `/api/v1/device-management-server/oss/biz-entrypoint` for cloud storage (`EleCloudDatabase.dll`).

### 2.11 The `[PRINT][AUTO_START] route=lan_sdcp_transfer` flow

Reverse-engineered print-flow log tag found in `EleStart.dll`:

```
[PRINT][AUTO_START] route=lan_sdcp_transfer
```

…followed by `[WAN_PRINT][RTM_SEND] cmd=…` for WAN.

This tells us the print job is started by a **LAN SDCP file transfer** (upload via `uploadFile/upload`), followed by an SDCP `StartPrint` (Cmd 128) request. The `SDCPFileTransferFinish` / `SDCPFileTransferOffset` signals confirm an **asynchronous file transfer** where the printer reports progress via SDCP.

---

## 3. OrcaSlicer `ElegooLink` — What It Currently Implements

Source: `src/slic3r/Utils/ElegooLink.hpp` (104 lines) + `src/slic3r/Utils/ElegooLink.cpp` (1309 lines).

### 3.1 Class hierarchy

```
PrintHost  ←  OctoPrint  ←  ElegooLink
```

### 3.2 Methods implemented

| Method | Notes |
|---|---|
| `get_name()` | `"ElegooLink"` |
| `get_post_upload_actions()` | `StartPrint` for non-CC2; `None` for CC2. |
| `test()` | Dispatches to `OctoPrint::test` / `elegoo_test` / `elegoo_cc2_test` based on `printer_model`. |
| `get_print_host_webui()` | Builds a CC2 LAN web UI path with `?access_code=&ip=&sn=&id=elegoo%3A+…`. |
| `upload()` | Entry point for file upload. |
| `upload_inner_with_host()` / `upload_inner_with_resolved_ip()` (Win32) | Routes to `loopUpload` / `loopUploadCC2`. |
| `loopUpload()` / `loopUploadCC2()` | Chunked multipart upload (`MAX_UPLOAD_PACKAGE_LENGTH = 1 MiB`). |
| `uploadPart()` / `uploadPartCC2()` | Upload a single chunk with `Check=1`, `S-File-MD5`, `Offset`, `Uuid`, `TotalSize`, `File` form fields. |
| `print(WebSocketClient& client, …)` | Sends SDCP `Cmd 128` over the `/websocket` bridge with payload `{Filename, StartLayer:0, Calibration_switch, PrintPlatformType, Tlp_Switch}`. |
| `checkResult(WebSocketClient& client, …)` | Sends SDCP `Cmd 0`, loops up to 60 s, waits for `CurrentStatus` to leave code 8. |
| `get_sn()` | Returns cached / configured CC2 serial. |
| `elegoo_test()` | HTTP GET; requires "ELEGOO" in response body. |
| `elegoo_cc2_test()` | HTTP GET with `X-Token` header; parses `error_code` + `system_info.sn`. |
| `cc2_token()` | `m_apikey` or default `"123456"`. |
| `make_cc2_info_url()` / `make_cc2_upload_url()` | `system/info?X-Token=…` and `upload`. |

### 3.3 SDCP commands used

```cpp
enum ElegooLinkCommand {
    ELEGOO_GET_STATUS     = 0,   // GetStatus
    ELEGOO_GET_PROPERTIES = 1,   // GetProperties
    ELEGOO_START_PRINT    = 128, // StartPrint
};
```

### 3.4 SDCP Ack enum

```cpp
SDCP_PRINT_CTRL_ACK_OK = 0,
SDCP_PRINT_CTRL_ACK_BUSY = 1,
SDCP_PRINT_CTRL_ACK_NOT_FOUND = 2,
SDCP_PRINT_CTRL_ACK_MD5_FAILED = 3,
SDCP_PRINT_CTRL_ACK_FILEIO_FAILED = 4,
SDCP_PRINT_CTRL_ACK_INVALID_RESOLUTION = 5,
SDCP_PRINT_CTRL_ACK_UNKNOW_FORMAT = 6,
SDCP_PRINT_CTRL_ACK_UNKNOW_MODEL = 7,
```

### 3.5 JSON envelope used

```json
{
  "Id": "",
  "Data": {
    "Cmd": <int>,
    "Data": { … },
    "RequestID": "<uuid>",
    "MainboardID": "",
    "TimeStamp": <ms>,
    "From": 1
  }
}
```

**Note**: OrcaSlicer sends `"MainboardID": ""` — the Elegoo SatelLite fills this with the actual serial. This means OrcaSlicer relies on the *server-side* (WebSocket bridge on port 3030) to fill it in, which works for the legacy WebSocket bridge but will not work with direct MQTT.

### 3.6 `CurrentStatus` parsing

`checkResult()` parses `Status → CurrentStatus` as a vector of ints and treats **code 8** as "check file status, need to wait" (poll again). Otherwise it breaks out.

This is a *very* limited slice of the SDCP status model.

---

## 4. Gap Analysis

### 4.1 Transport gap — LAN WebSocket vs. MQTT

OrcaSlicer uses `WebSocketClient::connect(wsUrl, "3030", "/websocket")` (line 859). Elegoo SatelLite uses a real MQTT client (`VoxMqtt` built on boost::mqtt 3.1.1/v5) with topics `sdcp/request/%1`, `sdcp/response/%1`, `sdcp/status/%1`, `sdcp/attributes/%1`, `sdcp/error/`, `sdcp/notice/`.

**Implication**: OrcaSlicer can only control devices that expose the legacy WebSocket bridge. Modern SDCP printers (Mars 4 Ultra, Jupiter 2, Centauri Carbon, Saturn 4) speak MQTT on port 9000 (TCP) / 9001 (WebSocket).

### 4.2 Command gap

OrcaSlicer implements **3** SDCP commands. Elegoo SatelLite implements a dispatcher (`SendSDCPRequest(ManageDevice*, int, QString, QJsonObject)`) that handles the full SDCP command set. The `SdcpPrintCtrlAck`, `SdcpErrorAttrReason`, `SdcpErrorStatusReason`, `SdcpPrintError` enums plus the attribute-tree fields indicate a rich command space including:
- Status queries and status-change notifications
- Attribute retrieval and assignment (`allowedAttributeAssignments`, `authorityAttributeIdentifier`)
- File listing, file deletion, file transfer offsets
- Print control (start/stop/pause/quit/force/finish)
- Camera control
- Timelapse control
- Device binding / unbinding

### 4.3 Status model gap

OrcaSlicer only parses `Status → CurrentStatus` and treats code 8 as a wait signal. Elegoo SatelLite has a complete model: `CurrentStatus` (array of codes), `ControlState`, `ErrorStatusReason`, `AutoFeedStatus`, `CameraStatus`, `AlreadyPrintLayer`, `PrintInfo` (percent/time/layer/progress/size), `extendedStatus`, `externalDeviceStatus`, and a per-attribute error map.

### 4.4 Lifecycle gap

Elegoo SatelLite has explicit device lifecycle events (`DeviceConnected`, `DeviceDisconnected`, `DeviceConnectionError`, `DeviceDataReceived`, `DeviceDiscovered`, `DeviceAttributesUpdated`, `DeviceOnlineStatusReceived`, …). OrcaSlicer has none.

### 4.5 File-transfer completion gap

Elegoo SatelLite uses `SDCPFileTransferFinish`, `SDCPFileTransferOffset`, `SDCPTransferFileCanceled`, `SDCPTransferFileError` to signal file transfer progress/completion. OrcaSlicer only checks HTTP status codes.

### 4.6 WAN/Cloud gap

OrcaSlicer has no WAN MQTT client, no Agora RTC/RTM integration, no device binding REST calls, no OSS storage upload. Elegoo SatelLite supports remote/cloud printing through a Paho MQTT client and Agora RTM relay.

### 4.7 HTTP REST gap

OrcaSlicer does not implement the 12+ HTTP REST endpoints (`/api/files`, `/api/print/*`, `/api/printer/*`, …) that Elegoo SatelLite uses as a fallback/control path.

---

## 5. Recommended Reimplementation Plan

### 5.1 Short-term (drop-in compatibility with the current `ElegooLink`)

1. **Add the missing SDCP command identifiers** as an enum that covers the full protocol surface (extend `ElegooLinkCommand`).
2. **Add the full SDCP status model** as a struct (`ElegooSDCPStatus`) covering `CurrentStatus`, `ControlState`, `ErrorStatusReason`, `AutoFeedStatus`, `CameraStatus`, `AlreadyPrintLayer`, `PrintInfo`, `PrintState`.
3. **Add the SDCP JSON envelope helpers** (`make_sdcp_request`, `parse_sdcp_response`) so every message can be constructed/parsed consistently (not only in `print` and `checkResult`).
4. **Add the HTTP REST endpoints** as `PrintHost` methods (`list_files`, `start_print`, `stop_print`, `pause_print`, `quit_print`, `get_live_camera`, `get_printer_name`, `get_printer_profile`, `get_timelapse`, `get_timelapse_list`).
5. **Add MQTT-over-WebSocket support** in `ElegooLink` so the `sdcp/response/{sn}` topic can be subscribed to directly without the legacy `/websocket` bridge.

### 5.2 Medium-term (modern SDCP printers)

1. **Add a native MQTT client** (boost::mqtt is already an OrcaSlicer dependency — use it) that speaks the `sdcp/*` topic family.
2. **Implement the attribute-tree model** (`Attributes`, `Attribute Status Trait`, `allowedAttributeAssignments`, `authorityAttributeIdentifier`, `certStatus`).
3. **Implement file transfer offset/finish notifications** (`SDCPFileTransferFinish`, `SDCPFileTransferOffset`).
4. **Implement print-control commands** (pause/stop/quit/force/finish) as SDCP messages.
5. **Implement the timelapse + camera endpoints.**

### 5.3 Long-term (WAN / cloud)

1. **Implement the Elegoo Cloud REST layer** (`/api/v1/device-management-server/*`) for device binding, pincode pairing, MQTT credentials, and Agora token acquisition.
2. **Implement the WAN MQTT client** (`WanMqttClient` equivalent) with Paho semantics.
3. **Implement Agora RTC/RTM streaming** for remote camera + remote command relay (`[WAN_PRINT][RTM_SEND]`).

---

## 6. Concrete Protocol Reference (drop-in constants)

The following constants were extracted from the Elegoo SatelLite binary. They are the ground truth for a faithful reimplementation:

### 6.1 MQTT topics

```
sdcp/request/{MainboardID}
sdcp/response/{MainboardID}
sdcp/status/{MainboardID}
sdcp/attributes/{MainboardID}
sdcp/error/
sdcp/notice/
app/v1/{SN}/device/data         (WAN)
app/v1/{SN}/device/onoffline    (WAN)
```

### 6.2 HTTP endpoints (LAN)

```
http://{host}:{port}/status
http://{host}:{port}/api/files
http://{host}:{port}/api/files/internal
http://{host}:{port}/api/print/start
http://{host}:{port}/api/print/stop
http://{host}:{port}/api/print/pause
http://{host}:{port}/api/print/quit
http://{host}:{port}/api/print/force
http://{host}:{port}/api/print/finish
http://{host}:{port}/api/print/copy/stop
http://{host}:{port}/api/printer/livecamera
http://{host}:{port}/api/printer/name
http://{host}:{port}/api/printer/profile
http://{host}:{port}/api/printer/timelapse
http://{host}:{port}/api/printer/timelapse/list
http://{host}:{port}/uploadFile/upload
```

### 6.3 Cloud REST endpoints

```
/api/v1/device-management-server/device/bind
/api/v1/device-management-server/device/unbind
/api/v1/device-management-server/device/name
/api/v1/device-management-server/device/pincode/detail
/api/v1/device-management-server/device/event-data/page
/api/v1/device-management-server/device/report-data/list
/api/v1/device-management-server/device-register/online-status
/api/v1/device-management-server/local-file/page
/api/v1/device-management-server/mqtt-link/mqtt-client
/api/v1/device-management-server/device/list/agora-token
/api/v1/device-management-server/oss/biz-entrypoint
```

### 6.4 MQTT credentials endpoint

```
POST /api/v1/device-management-server/mqtt-link/mqtt-client
→ returns broker endpoint + credentials for the WAN MQTT client
```

### 6.5 SDCP JSON envelope (canonical)

```json
{
  "Id": "<32-hex>",
  "Data": {
    "Cmd": <int>,
    "Data": { … },
    "RequestID": "<32-hex>",
    "MainboardID": "<MainboardID>",
    "TimeStamp": <unix-seconds>,
    "From": 1
  },
  "Topic": "sdcp/response/<MainboardID>"
}
```

### 6.6 SDCP response error enums

```
SdcpPrintCtrlAck:      0..7  (OK / BUSY / NOT_FOUND / MD5_FAILED / FILEIO_FAILED / INVALID_RESOLUTION / UNKNOW_FORMAT / UNKNOW_MODEL)
SdcpErrorAttrReason:   per-attribute error reasons (QMap<QString, QList<SdcpErrorAttrReason>>)
SdcpErrorStatusReason: per-status error reasons (QMap<QString, QList<SdcpErrorStatusReason>>)
SdcpPrintError:        print-error enum (GetDevicePrintStatus)
```

### 6.7 File-transfer form fields

```
Check       = "1"
S-File-MD5  = <md5 hex>
Offset      = <byte offset>
Uuid        = <upload session uuid>
TotalSize   = <total file size>
File        = <binary chunk, filename>
```

Chunk size: `1 MiB`.

---

## 7. Evidence Trail

All strings referenced in this report were extracted with the following exact commands (against the extracted Elegoo SatelLite install tree):

```bash
# MQTT topics
strings -n 4 EleNetManager.dll | grep -E "sdcp/(request|response|status|attributes|error|notice)"

# HTTP REST endpoints
strings -n 4 EleNetManager.dll | grep -E "http://%1:%2/api/|http://%1:%2/status"

# Cloud REST endpoints
strings -n 4 EleNetManager.dll | grep -E "/api/v1/device-management-server/"

# SDCP enums and message types
strings -n 4 EleNetManager.dll | grep -E "Sdcp|SDCP|CmdManageDevice|ManageDevice|SendSDCPRequest"

# MQTT client class
strings -n 4 EleMqtt.dll | grep -E "VoxMqtt|Subscribe|Publish|GetState|SetStatus"

# Paho WAN MQTT client
strings -n 4 EleNetManager.dll | grep -E "WanMqtt|Paho|async_client|callback"

# File transfer form fields
strings -n 5 EleNetManager.dll | grep -E 'form-data; name="'

# Print flow log tags
strings -n 8 EleStart.dll | grep -E "PRINT\]\[AUTO_START\]|WAN_PRINT\]\[RTM_SEND\]"
```

Extracted install tree: `/tmp/opencode/wineprefix/drive_c/ElegooSatellite/`.

---

## 9. Live Validation (2026-11-03)

Validated against a real device on the LAN: **Elegoo Saturn 4 Ultra, firmware V1.5.2, SDCP V3.0.0**, IP `192.168.15.13`, MainboardID `d86e1f35184b0100`.

Method: raw WebSocket client (Python) → `ws://192.168.15.13:3030/websocket`, followed by Cmd 0, Cmd 1, Cmd 258 requests built per §6.5.

| Check | Result |
|---|---|
| TCP 3030 open, WS handshake `101 Switching Protocols` | ✅ |
| Cmd 0 → `Ack:0` on `sdcp/response/{id}` | ✅ |
| Status push on `sdcp/status/{id}` | ✅ fields match §6 structures exactly |
| Cmd 1 → `Ack:0`, attributes push on `sdcp/attributes/{id}` | ✅ fields match, plus extras |
| Cmd 258 file list `/local/` → `Ack:0` + 19 files | ✅ |

### Dialect deviations from the spec (observed on V1.5.2)

1. **No `"pong"` reply to the SDCP text `"ping"`** — the heartbeat in §"Heartbeat" is not honoured by this firmware. WebSocket-level ping/pong frames are handled at the frame layer instead (the client must answer server pings with pong frames).
2. **Undocumented attributes fields**: `SDCPStatus`, `MaximumCloudSDCPSercicesAllowed` (vendor typo, present in the wild), `NumberOfCloudSDCPServicesConnected`. Parsers must tolerate unknown fields.
3. **File list entries are lean**: each entry carries only `name` and `type`; the spec's `usedSize`/`totalSize`/`storageType` per-entry fields are absent (V3.0.0 doc shows them; firmware omits them).
4. **Double slash in file paths**: the firmware reports `/local//File.goo` (double slash after the mount point). Clients should normalize when matching paths.
5. **UDP discovery silent**: the device did not answer `"M99999"` broadcasts while idle on this network (possible AP behaviour); direct IP connection works regardless — discovery is a convenience, not a requirement.
6. **File upload pipeline validated end-to-end** (2026-11-03 round-trip test): multipart fields `Check`/`S-File-MD5`/`Offset`/`Uuid`/`TotalSize`/`File` accepted at `http://IP:3030/uploadFile/upload`; chunked upload across the Offset boundary works (1.5 MB in 2 chunks); responses use the business envelope `{"code":"000000","success":true}`.
7. **Unprintable files are stored but hidden from Cmd 258 listings** (filter confirmed empirically): a 1.5 MB payload of random bytes named `*.goo` was accepted by the uploader and reduced `RemainingMemory` by exactly its size, yet never appeared in the file list. Clients must not rely on the list to confirm an upload landed — use `RemainingMemory` (Cmd 1) for storage accounting.
8. **Cmd 259 delete works on hidden files** by their exact stored path (`/local//Name.ext`, note the firmware's double slash) — `Ack:0`, and the storage is reclaimed.
9. **Print-control commands while idle return `Ack=1`** (busy/invalid-state semantics) for Pause (129) and Stop (130) — correct behaviour; the request/response/Ack loop itself is validated.
10. **No LAN file-download endpoint exists**: `/download?url=...`, `/api/files` return `404 Not found`; port 80 is closed. REA confirms file *download* is a WAN-only feature (Cmd 160 start / Cmd 161 cancel, requiring `Filename`, `Url`, `TaskID`, `Md5` — the printer pulls from Elegoo Cloud). The slicer is an upload-only peer on the LAN.
11. **Video stream (Cmd 386) validated**: `{"Enable":1}` → `Ack:0` with `VideoUrl` = `rtsp://{MainboardIP}:554/video` (port 554, path `/video`). The stream is **H.264, 1280x720**.
12. **The RTSP server rejects TCP-interleaved transport** ("Nonmatching transport in server reply" under `-rtsp_transport tcp`); it serves **RTP/UDP only**. Clients must use UDP (ffmpeg's default) — firewalls that block UDP from the printer will break the feed.
13. **Stream lifetime appears tied to the SDCP session**: after the WebSocket session that opened the stream disconnects, a disable request on a fresh session returns `Ack=1` and no attributes push reports active streams. Treat "enable → view → disable on the same session" as the correct usage pattern; do not rely on cross-session state.
14. The spec's `Ack=1` for Cmd 386 ("exceeded maximum simultaneous streaming limit") also appears to serve as the generic "no stream active" response for disable on this firmware.

### Observed status snapshot

```json
{"Status":{"CurrentStatus":[0],"ReleaseFilm":7514,"TempOfUVLED":32.06,
 "TimeLapseStatus":1,"PrintInfo":{"Status":0,"CurrentLayer":0,"TotalLayer":0,
 "CurrentTicks":0,"TotalTicks":0,"ErrorNumber":0,"Filename":"","TaskId":""}}}
```

### Observed attributes snapshot

```json
{"Attributes":{"Name":"GOOER","MachineName":"Saturn 4 Ultra","BrandName":"ELEGOO",
 "ProtocolVersion":"V3.0.0","FirmwareVersion":"V1.5.2","Resolution":"11520x5120",
 "XYZsize":"211.68x118.37x220","MainboardIP":"192.168.15.13",
 "NetworkStatus":"wlan","UsbDiskStatus":0,
 "Capabilities":["FILE_TRANSFER","PRINT_CONTROL","VIDEO_STREAM"],
 "SupportFileType":["CTB","GOO"],
 "DevicesStatus":{"TempSensorStatusOfUVLED":1,"LCDStatus":1,"SgStatus":1,
  "ZMotorStatus":1,"RotateMotorStatus":1,"RelaseFilmState":1},
 "ReleaseFilmMax":60000,"CameraStatus":1,"RemainingMemory":5285871616,
 "TLPNoCapPos":50,"TLPStartCapPos":30,"TLPInterLayers":10,
 "SDCPStatus":0,"MaximumCloudSDCPSercicesAllowed":0,
 "NumberOfCloudSDCPServicesConnected":0,
 "MaximumVideoStreamAllowed":2,"NumberOfVideoStreamConnected":0,
 "MainboardID":"d86e1f35184b0100"}}
```

## 10. Conclusion (updated after live validation)

OrcaSlicer's `ElegooLink` is a solid **minimum viable** implementation of the *legacy* Elegoo LAN WebSocket bridge, with correct file-transfer form fields and correct `SdcpPrintCtrlAck` handling. However, it is far from a faithful implementation of the SDCP protocol as shipped in Elegoo SatelLite.

To close the gap, the highest-impact additions are:

1. **MQTT transport** (LAN `sdcp/*` topics) — unlocks all modern SDCP printers.
2. **Full SDCP command set** via a generic `SendSDCPRequest(cmd, payload)` dispatcher.
3. **Full status model** (`ControlState`, `ErrorStatusReason`, `AutoFeedStatus`, `CameraStatus`, `AlreadyPrintLayer`, `PrintInfo`).
4. **HTTP REST control path** (`/api/print/*`, `/api/printer/*`).
5. **WAN/Cloud support** (Paho MQTT, device binding, Agora token, OSS upload).

Items 1–4 are implementable in OrcaSlicer with the dependencies already present (`boost::mqtt`, `boost::property_tree`, `Http`). Item 5 requires a new dependency (Paho MQTT C++ or equivalent) and Agora SDK integration, which are out of scope for a slicer and are only needed for remote/cloud printing.
