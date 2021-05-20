#include <Arduino.h>

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include <SoftwareSerial.h>
#include <ArduinoOTA.h>
#include <AESLib.h>

#include <arduino_secrets.h>

const char* ssid 		      = SECRET_SMARTHOME_WIFI_SSID;
const char* password 		  = SECRET_SMARTHOME_WIFI_PASSWORD;
const char* mqttServer	  = SECRET_MQTT_SERVER;
const int   mqttPort 		  = SECRET_MQTT_PORT;
const char* mqttUser 		  = SECRET_MQTT_USER;
const char* mqttPassword 	= SECRET_MQTT_PASSWORD;

// ==============================================================================
// AES CBC
// ==============================================================================

AESLib aesLib;

byte aes_iv[16]    = { 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58, 0x56, 0x2e };
byte aes_key[16]   = { 0x37, 0x37, 0x37, 0x39, 0x33, 0x38, 0x44, 0x39, 0x30, 0x46, 0x37, 0x30, 0x34, 0x45, 0x35, 0x42 };
byte enc_iv_to[16] = {};
byte cleartext[16] = {};

char readbuffer[] = "vcT9bEapirfUZNyq";
unsigned char encoded[sizeof(readbuffer) * 2] = "";
char aes_send[32] = "";

// ==============================================================================
// S8 Init zone
// ==============================================================================

#define D7 (13)
#define D8 (15)
#define CO2_INTERVAL 15000

SoftwareSerial s8Serial(D7, D8);

int s8_co2;
int s8_co2_mean;
int s8_co2_mean2;

float smoothing_factor = 0.5;
float smoothing_factor2 = 0.15;

byte cmd_s8[]       = {0xFE, 0x04, 0x00, 0x03, 0x00, 0x01, 0xD5, 0xC5};
byte abc_s8[]       = {0xFE, 0x03, 0x00, 0x1F, 0x00, 0x01, 0xA1, 0xC3};
byte response_s8[7] = {0, 0, 0, 0, 0, 0, 0};

const int r_len = 7;
const int c_len = 8;

long lastCo2Measured = 0;

// ==============================================================================
// End S8 init zone
// ==============================================================================

unsigned int multicast_port = 9898;
unsigned int unicast_port   = 8989;

long lastReconnectAttempt = 0;

IPAddress multicast_ip_addr = IPAddress(224, 0, 0, 50);

char mPacket[255];
char uPacket[255];

WiFiUDP mUdp;
WiFiUDP uUdp;

WiFiClient espClient;
PubSubClient client(espClient);

char hostname[]      = "charon";

char mqtt_topic_status_base[] = "esp/status/";
char mqtt_topic_data_base[] = "esp/sensors/co2/";

char mqtt_topic_status[sizeof(mqtt_topic_status_base) + sizeof(hostname) + 5];
char mqtt_topic_data[sizeof(mqtt_topic_data_base) + sizeof(hostname) + 5];

StaticJsonDocument<200> co2_data_doc;

boolean mqtt_reconnect() {
  Serial.print("Connecting to MQTT...");
  if(client.connect(hostname, mqttUser, mqttPassword, mqtt_topic_status, 2, true, "offline")) {
    // Online Message
    client.publish(mqtt_topic_status, "online", true);
    client.subscribe("esp/04cf8cf2ee25/CMD");
    client.subscribe("esp/04cf8cf2ee25/heartbeat");
  } else {
    Serial.printf("failed with state: %d\n", client.state());
  }
  return client.connected();
}

boolean wifi_reconnect() {
  Serial.printf("Connecting to %s ", ssid);
  WiFi.hostname(hostname);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }

  co2_data_doc["IP"] = WiFi.localIP().toString();

  mUdp.beginMulticast(WiFi.localIP(), multicast_ip_addr, multicast_port);
  uUdp.begin(unicast_port);

  ArduinoOTA.setPort(8266);
  ArduinoOTA.setHostname(hostname);
  // ArduinoOTA.setPassword("admin");

  ArduinoOTA.onStart([]() {
    String type;
    if (ArduinoOTA.getCommand() == U_FLASH) {
      type = "sketch";
    } else { // U_FS
      type = "filesystem";
    }

    Serial.println("Start updating " + type);
  });
  ArduinoOTA.onEnd([]() {
    Serial.println("\nEnd");
  });
  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    Serial.printf("Progress: %u%%\r", (progress / (total / 100)));
  });
  ArduinoOTA.onError([](ota_error_t error) {
    Serial.printf("Error[%u]: ", error);
    if (error == OTA_AUTH_ERROR) {
      Serial.println("Auth Failed");
    } else if (error == OTA_BEGIN_ERROR) {
      Serial.println("Begin Failed");
    } else if (error == OTA_CONNECT_ERROR) {
      Serial.println("Connect Failed");
    } else if (error == OTA_RECEIVE_ERROR) {
      Serial.println("Receive Failed");
    } else if (error == OTA_END_ERROR) {
      Serial.println("End Failed");
    }
  });
  ArduinoOTA.begin();

  return true;
}

void encrypt_to_ciphertext(char * msg, uint16_t msgLen, byte iv[]) {
  aesLib.encrypt((byte*)msg, msgLen, (char*)encoded, aes_key, sizeof(aes_key), iv);
  return;
}

void callback(char* topic, byte* payload, unsigned int length) {
  char buff_p[length];

  for (size_t i = 0; i < length; i++)
  {
    buff_p[i] = (char)payload[i];
  }
  buff_p[length] = '\0';

  if (strcmp(topic,"esp/04cf8cf2ee25/CMD")==0){
    // Сперва получить ключ, вне зависимости от содержания
    memset(aes_send, 0, sizeof(aes_send));
    sprintf((char*)cleartext, "%s", readbuffer);
    memcpy(enc_iv_to, aes_iv, sizeof(aes_iv));
    uint16_t msgLen = sizeof(cleartext);
    encrypt_to_ciphertext((char*)cleartext, msgLen, enc_iv_to);

    for (size_t i = 0; i < sizeof(enc_iv_to); i++)
    {
      char ch[sizeof(enc_iv_to[i])] = "";
      memset(ch, 0, sizeof(ch));
      sprintf(ch, "%02X", enc_iv_to[i]);
      strcat (aes_send, ch);
    }
    // Вариант "в лоб", без использования цикла
    //sprintf(aes_send, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", enc_iv_to[0], enc_iv_to[1],enc_iv_to[2],enc_iv_to[3],enc_iv_to[4],enc_iv_to[5],enc_iv_to[6], enc_iv_to[7], enc_iv_to[8],enc_iv_to[9],enc_iv_to[10],enc_iv_to[11],enc_iv_to[12],enc_iv_to[13],enc_iv_to[14],enc_iv_to[15]);

    if(strcmp(buff_p, "ON")==0) {
      char udpPayload[150] = "{\"cmd\":\"write\",\"model\":\"gateway\",\"sid\":\"4cf8cf2ee25\",\"data\":\"{\"key\":\"";
      strcat(udpPayload, aes_send); 
      strcat(udpPayload, "\",\"rgb\":838795264}\"}");

      IPAddress gIP(192, 168, 2, 9);
      uUdp.beginPacket(gIP, multicast_port);
      uUdp.write(udpPayload);
      uUdp.endPacket();

      memset(udpPayload, 0, sizeof(udpPayload));
      strcat(udpPayload, "{\"cmd\":\"read\",\"sid\":\"4cf8cf2ee25\"}");
      uUdp.beginPacket(gIP, multicast_port);
      uUdp.write(udpPayload);
      uUdp.endPacket();

    } else if (strcmp(buff_p, "OFF")==0) {
      char udpPayload[150] = "{\"cmd\":\"write\",\"model\":\"gateway\",\"sid\":\"4cf8cf2ee25\",\"data\":\"{\"key\":\"";
      strcat(udpPayload, aes_send); 
      strcat(udpPayload, "\",\"rgb\":0}\"}");

      IPAddress gIP(192, 168, 2, 9);
      uUdp.beginPacket(gIP, multicast_port);
      uUdp.write(udpPayload);
      uUdp.endPacket();

      memset(udpPayload, 0, sizeof(udpPayload));
      strcat(udpPayload, "{\"cmd\":\"read\",\"sid\":\"4cf8cf2ee25\"}");
      uUdp.beginPacket(gIP, multicast_port);
      uUdp.write(udpPayload);
      uUdp.endPacket();

    } else {
      Serial.print("UNKNOWN CMD");
      Serial.println();
    }
  }
  if (strcmp(topic,"esp/04cf8cf2ee25/heartbeat")==0){
    memset(readbuffer, 0, sizeof(readbuffer));
    StaticJsonDocument<256> doc;
    deserializeJson(doc, payload, length);
    strlcpy(readbuffer, doc["token"] | "default", sizeof(readbuffer));
  }
}

void s8Request(byte cmd[]) { 
  s8Serial.begin(9600);
  while(!s8Serial.available()) {
    s8Serial.write(cmd, c_len); 
    delay(50);
  }
  int timeout=0;
  while(s8Serial.available() < r_len ) {
    timeout++;
    if(timeout > 10) {
      while(s8Serial.available()) {
        s8Serial.read(); 
        break;
      }
    } 
    delay(50); 
  } 
  for (int i=0; i < r_len; i++) { 
    response_s8[i] = s8Serial.read(); 
  }
  
  s8Serial.end();
}    

unsigned long s8Replay(byte rc_data[]) { 
  int high = rc_data[3];
  int low = rc_data[4];
  unsigned long val = high*256 + low;
  return val; 
}

boolean co2_measure() {
  s8Request(cmd_s8);
  s8_co2 = s8Replay(response_s8);
  
  if (!s8_co2_mean) s8_co2_mean = s8_co2;
  s8_co2_mean = s8_co2_mean - smoothing_factor*(s8_co2_mean - s8_co2);
  
  if (!s8_co2_mean2) s8_co2_mean2 = s8_co2;
  s8_co2_mean2 = s8_co2_mean2 - smoothing_factor2*(s8_co2_mean2 - s8_co2);

  co2_data_doc["current"] = s8_co2;
  co2_data_doc["mean"] = s8_co2_mean;
  co2_data_doc["mean2"] = s8_co2_mean2;

  return true;
}

void get_abc() {
  int abc_s8_time;
  s8Request(abc_s8);
  abc_s8_time = s8Replay(response_s8);
  co2_data_doc["abc"] = abc_s8_time;
  return;
}

void setup() {
  Serial.begin(115200);
  if(WiFi.status() != WL_CONNECTED) {
    wifi_reconnect();
  }

  client.setServer(mqttServer, mqttPort);
  client.setCallback(callback);
  mqtt_reconnect();
  strcpy(mqtt_topic_status, mqtt_topic_status_base);
  strcat(mqtt_topic_status, hostname);

  strcpy(mqtt_topic_data, mqtt_topic_data_base);
  strcat(mqtt_topic_data, hostname);

  get_abc();
}

void loop() {

  ArduinoOTA.handle();

  if (WiFi.status() != WL_CONNECTED) {
    wifi_reconnect();
  }

  if(!client.connected()) {
    long now = millis();
    if(now - lastReconnectAttempt > 5000) {
      lastReconnectAttempt = now;
      if(mqtt_reconnect()) {
        lastReconnectAttempt = 0;
      }
    }
  } else {
    client.loop();
  }

  long co2_time = millis();
  if(co2_time - lastCo2Measured > CO2_INTERVAL) {
    co2_measure();
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    size_t n = serializeJson(co2_data_doc, buffer);
    client.publish(mqtt_topic_data, buffer, n);
    lastCo2Measured = co2_time;
  }

  int mPkSize = mUdp.parsePacket();
  //unsigned int pub_status = 0;
  if (mPkSize) {
    int len = mUdp.read(mPacket, 255);
    if (len > 0) {
      mPacket[len] = 0;
    }

    char jsonPacket[255];
    strcpy(jsonPacket, mPacket);

    const size_t capacity = JSON_OBJECT_SIZE(3) + JSON_ARRAY_SIZE(2) + 60;
    DynamicJsonDocument doc(capacity);
    deserializeJson(doc, jsonPacket);

    char topic[50] = "esp/";
    strcat (topic, doc["sid"].as<char*>());
    strcat (topic, "/");
    strcat (topic, doc["cmd"].as<char*>());

    char SID[25];
    strcpy(SID, doc["sid"].as<char*>());

    // Serial.printf("UDP packet [%d bytes] contents: %s\n", mPkSize, mPacket);
    client.publish(topic, mPacket, true);

    // Request status
    char ack_data[50] = "{\"cmd\":\"read\",\"sid\":\"";
    strcat(ack_data, SID);
    strcat(ack_data, "\"}");
    
    uUdp.beginPacket(mUdp.remoteIP(), multicast_port);
    uUdp.write(ack_data);
    uUdp.endPacket();

    // Read answer
    int uPkSize = uUdp.parsePacket();
    if (uPkSize) {
      len = uUdp.read(uPacket, 255);
      if (len > 0) {
        uPacket[len] = 0;
      }
    }

    if(uUdp.remoteIP() == mUdp.remoteIP()) {
      char topic[50] = "esp/";
      strcat (topic, SID);
      strcat (topic, "/read_ack");
      client.publish(topic, uPacket);

      char ujsonPacket[255];
      strcpy(ujsonPacket, uPacket);
      const size_t ucapacity = JSON_OBJECT_SIZE(3) + JSON_ARRAY_SIZE(2) + 60;
      DynamicJsonDocument udoc(ucapacity);
      deserializeJson(udoc, ujsonPacket);
      memset(topic, 0, sizeof(topic));
      strcat (topic, "esp/");
      strcat (topic, SID);
      strcat (topic, "/status");
      client.publish(topic,  udoc["data"], true);
    }
  }

}