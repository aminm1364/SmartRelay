/**************************** SMART RELAY ***************************
 *                                                                  *
 *      This is a Basic project to control MCU ESP8266MOD 12-F      *
 *      and of course compatible with aother Arduino platforms.     *
 *                                                                  *
 *      It uses MQTT messaging system, saves the configuration on   *
 *    the built-in ROM, has encryption and dycription library ready *
 *    and AOT enabled to get the new updates over the air.          *
 *                                                                  *
 *    If you find it useful or interesting, feel free to fork the   *
 *    branch and make it more helpful and interesting for everyone  *
 *                                                                  *
 *    Best wishes. AminM                                            *
 ********************************************************************/

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ESP8266Ping.h>
#include <ESP8266httpUpdate.h>
#include <NTPClient.h>
#include <AES.h>
#include <EEPROM.h>
#include <Crypto.h>
#include <string.h>
#include <ArduinoJson.h>

// Function prototypes
void enterConfigurationMode();
bool validateEntry(const String &entry, const String &field);
void saveConfigurationToEEPROM(const String &configJson);
String readConfigurationFromEEPROM(const bool decrypt);
String getSerialInput(const String &prompt, const String &validationType, bool encryptData = false);

const char *ssid = nullptr;
const char *password = nullptr;

// MQTT server credentials
const char *mqtt_server = nullptr;
int mqtt_port;
const char *mqtt_user = nullptr;
const char *mqtt_password = nullptr;
const char *mqtt_authentication = nullptr;

// Topics
const char *mqtt_topic = nullptr;
const char *mqtt_publish_topic = nullptr;

// OTA update server details
const char *ota_url = nullptr; //"http://your-github-server-or-other-host.com/firmware.bin";

// Relay pin
const int statusLED = 16; // D0
int relayPin;

byte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; // 128-bit key
AES128 aes128;                                                                                                   // Create AES object
char inputString[17];                                                                                            // To store 16 characters + 1 null-terminator
int inputIndex = 0;

// NTP setup
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP);

/*
  entry D0 OR 16 -> board LET - Second (HIGH -> OFF, LOW -> ON) + agains PIN_D0 on the board (HIGH -> ON, LOW -> OFF)
  entry 2 OR D4  -> board LET - Main (HIGH -> OFF, LOW -> ON) + PIN_D4 Inv (HIGH -> ON, LOW -> OFF)

  entry 5 OR D1  -> PIN_D1 Inv (HIGH -> ON, LOW -> OFF)
  entry 4 OR D2  -> PIN_D2 Inv (HIGH -> ON, LOW -> OFF)
  entry 0 OR D3  -> PIN_D3 Inv (HIGH -> ON, LOW -> OFF)
  entry 2 OR D4  -> PIN_D4 Inv (HIGH -> ON, LOW -> OFF) ALSO board LED second NOT INV (HIGH -> OFF, LOW -> ON)
  entry 14 OR D5 -> PIN_D3 Inv (HIGH -> ON, LOW -> OFF)
  entry 12 OR D6 -> PIN_D3 Inv (HIGH -> ON, LOW -> OFF)
  entry 13 OR D7 -> PIN_D3 Inv (HIGH -> ON, LOW -> OFF)
  entry 15 OR D8 -> PIN_D3 Inv (HIGH -> ON, LOW -> OFF)
  entry 3  -> RX
  entry 1  -> TX (RX and TX are primarily used for serial communication)

  entry 10       -> PIN_SD3 Inv (HIGH -> ON, LOW -> OFF)
  entry 9        -> PIN_SD2 Inv (HIGH -> ON, LOW -> OFF)
  entry 8        -> PIN_SD1 Inv (HIGH -> ON, LOW -> OFF)
  entry 7        -> PIN_SD0 Inv (HIGH -> ON, LOW -> OFF)

*/
WiFiClient espClient;
PubSubClient client(espClient);

void statusBlinking(const int numberOfBlinking)
{
  digitalWrite(statusLED, HIGH);
  delay(2000);
  digitalWrite(statusLED, LOW);
  delay(1000);
  digitalWrite(statusLED, HIGH);
  for (int i = 0; i <= numberOfBlinking; i++)
  {
    digitalWrite(statusLED, HIGH);
    delay(200);
    digitalWrite(statusLED, LOW);
    delay(300);
    digitalWrite(statusLED, HIGH);
  }
}

void statusheartbeat(const bool isAlive)
{
  if (isAlive)
  {
    digitalWrite(statusLED, LOW);
    delay(3);
    digitalWrite(statusLED, HIGH);
  }
  else
  {
    digitalWrite(statusLED, LOW);
    delay(500);
    digitalWrite(statusLED, HIGH);
    delay(500);
    digitalWrite(statusLED, LOW);
    delay(500);
    digitalWrite(statusLED, HIGH);
  }
}

void checkforExistingConfiguration()
{
  Serial.println("Checking for existing configuration...");
  byte savedData[16];
  bool dataAvailable = false;

  // Read from EEPROM (first 16 bytes reserved for the encrypted string)
  for (int i = 0; i < 16; i++)
  {
    savedData[i] = EEPROM.read(i);
  }

  // If the first byte is not 0xFF, we assume it's valid data
  if (savedData[0] != 0xFF)
  {
    Serial.println("Encrypted data found in EEPROM!");
    byte decrypted[16];
    aes128.decryptBlock(decrypted, savedData); // Decrypt the stored data

    // Print the decrypted string
    Serial.print("Decrypted String: ");
    for (int i = 0; i < 16; i++)
    {
      Serial.print((char)decrypted[i]);
    }
    Serial.println();
  }
  else
  {
    Serial.println("No encrypted data found in EEPROM.");
  }
}

// Function to connect to WiFi
void setupWiFi()
{
  delay(10);
  Serial.println("Connecting to WiFi...");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.println();
  Serial.print("WiFi connected with ip ");
  Serial.println(WiFi.localIP());
}

void pingServer()
{
  Serial.print("Pinging host ");
  Serial.println(mqtt_server);

  if (Ping.ping(mqtt_server, 5))
  {
    Serial.println("Success!!");
  }
  else
  {
    Serial.println("Error :(");
  }
}

void RelayStatusOFF()
{
  digitalWrite(relayPin, LOW);
  Serial.println("Relay turned OFF");
}

void RelayStatusON()
{
  digitalWrite(relayPin, HIGH);
  Serial.println("Relay turned ON");
}

// Get formatted timestamp
String getTimestamp()
{
  timeClient.update();

  return timeClient.getFormattedTime();
}

// Publish a message to MQTT
void publishMessage(const char *message)
{
  String timestamp = getTimestamp();
  String fullMessage = String(message) + " | Timestamp: " + timestamp;
  if (client.connected())
  {
    client.publish(mqtt_publish_topic, fullMessage.c_str());
    Serial.printf("Published: %s\n", fullMessage.c_str());
  }
  else
  {
    Serial.println("Failed to publish message. Not connected to MQTT.");
  }
}

// MQTT message callback
void callback(char *topic, byte *payload, unsigned int length)
{
  String message = "";
  for (unsigned int i = 0; i < length; i++)
  {
    message += (char)payload[i];
  }

  // Add basic security check (example: check for an authorization token in the message)
  if (message.startsWith(mqtt_authentication))
  {                                                                  // Replace with your security logic
    String command = message.substring(strlen(mqtt_authentication)); // Assuming token length is 15 chars
    Serial.println(command);
    if (command == "ON")
    {
      RelayStatusON();
      publishMessage("Relay is now ON! UFFF!!");
    }
    else if (command == "OFF")
    {
      RelayStatusOFF();
      publishMessage("Relay is now OFF! UFFF!!");
    }
  }
  else
  {
    Serial.println("Unauthorized command!");
  }
}

// Function to connect to MQTT broker
void connectMQTT()
{
  while (!client.connected())
  {
    Serial.println("Connecting to MQTT...");
    if (client.connect("ESP8266Client", mqtt_user, mqtt_password))
    {
      Serial.println("Connected to MQTT");
      client.subscribe(mqtt_topic);
    }
    else
    {
      Serial.print("Failed to connect, retrying in 5 seconds. State: ");
      Serial.println(client.state());
      statusheartbeat(false);
      delay(5000);
    }
  }
}

// Function for OTA updates
void checkForUpdates()
{
  Serial.println("Checking for OTA update...");
  t_httpUpdate_return result = ESPhttpUpdate.update(espClient, ota_url, "");

  switch (result)
  {
  case HTTP_UPDATE_FAILED:
    Serial.printf("Update failed: %s\n", ESPhttpUpdate.getLastErrorString().c_str());
    break;
  case HTTP_UPDATE_NO_UPDATES:
    Serial.println("No updates available.");
    break;
  case HTTP_UPDATE_OK:
    Serial.println("Update successful, restarting...");
    ESP.restart();
    break;
  }
}

void GetSavedConfigurations(const String &config)
{
  StaticJsonDocument<256> jsonDoc;
  DeserializationError error = deserializeJson(jsonDoc, config);
  if (error)
  {
    Serial.println("Failed to parse configuration JSON.");
    return;
  }

  // Extract values
  String wifiSSID = jsonDoc["wifiSSID"];
  String wifiPassword = jsonDoc["wifiPassword"];
  String mqttHost = jsonDoc["mqttHost"];
  int mqttPort = jsonDoc["mqttPort"];
  String mqttUsername = jsonDoc["mqttUsername"];
  String mqttPassword = jsonDoc["mqttPassword"];
  String authToken = jsonDoc["authToken"];
  String mqttTopic = jsonDoc["mqttTopic"];
  String mqttPublishTopic = jsonDoc["mqttPublishTopic"];
  String otaUrl = jsonDoc["otaUrl"];
  int relayPinNumber = jsonDoc["relayPinNumber"];

  Serial.println("Loading Configuration:");
  ssid = strdup(wifiSSID.c_str());
  password = strdup(wifiPassword.c_str());

  // MQTT server credentials
  mqtt_server = strdup(mqttHost.c_str());
  mqtt_port = mqttPort;
  mqtt_user = strdup(mqttUsername.c_str());
  mqtt_password = strdup(mqttPassword.c_str());
  mqtt_authentication = strdup(authToken.c_str());
  mqtt_topic = strdup(mqttTopic.c_str());
  mqtt_publish_topic = strdup(mqttPublishTopic.c_str());
  ota_url = strdup(otaUrl.c_str());
  relayPin = relayPinNumber;
}

void ConfigurationCheck()
{
  // Check for existing configuration
  Serial.println("Checking for saved data in EEPROM...");
  String config = readConfigurationFromEEPROM(false);
  if (config[0] != 0xFF)
  {
    // Prompt user for reconfiguration
    Serial.println("Configuration has been found. Do you want to reconfigure? (Press Enter to start) (Waiting time: [5] sec.)");
    unsigned long startTime = millis();
    while (millis() - startTime < 5000)
    {
      if (Serial.available() > 0)
      {
        if (Serial.read() == '\n')
        {
          enterConfigurationMode();
          return;
        }
      }
    }
    Serial.println("No reconfiguration requested. Proceeding with the existing configuration.");
    GetSavedConfigurations(config);
  }
  else
  {
    Serial.println("No configuration found in EEPROM. Entering configuration mode.");
    enterConfigurationMode();
  }
}

void setup()
{
  Serial.begin(9600);
  EEPROM.begin(512);          // Initialize EEPROM
  pinMode(statusLED, OUTPUT); // declare onboard LED as output
  pinMode(relayPin, OUTPUT);  // declare relay as output
  digitalWrite(relayPin, HIGH);
  digitalWrite(statusLED, LOW);

  ConfigurationCheck();
  statusBlinking(1);

  statusBlinking(2);
  setupWiFi();
  pingServer();
  statusBlinking(3);
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);
  timeClient.begin();
  Serial.println("Setup complete.");
  statusBlinking(4);
}

void loop()
{
  if (!client.connected())
  {
    connectMQTT();
  }
  client.loop();

  static unsigned long lastheartbeatInterval = 0;
  static unsigned long heartbeatInterval = 4000;

  if (millis() - lastheartbeatInterval > heartbeatInterval)
  {
    lastheartbeatInterval = millis();
    statusheartbeat(true);
    // publishMessage("ESP8266-Client01.status-> connected");
  }

  static unsigned long lastUpdateCheck = 0;
  const unsigned long updateInterval = 3600000; // Check for updates every hour

  if (millis() - lastUpdateCheck > updateInterval)
  {
    lastUpdateCheck = millis();
    checkForUpdates();
  }
}

// Save JSON configuration to EEPROM
void saveConfigurationToEEPROM(const String &configJson)
{
  for (unsigned i = 0; i < configJson.length(); i++)
  {
    EEPROM.write(i, configJson[i]);
  }

  EEPROM.commit();
}

// Read and decrypt configuration from EEPROM
String readConfigurationFromEEPROM(const bool decrypt)
{
  String configJson;
  byte savedData[512];

  for (int i = 0; i < 512; i++)
  {
    savedData[i] = EEPROM.read(i);
  }

  if (decrypt)
  {
    byte decrypted[512] = {0};
    aes128.decryptBlock(decrypted, savedData); // Decrypt the data block

    for (int i = 0; i < 512 && decrypted[i] != '\0'; i++)
    {
      configJson += (char)decrypted[i];
    }
  }
  else
  {
    for (int i = 0; i < 512 && savedData[i] != '\0'; i++)
    {
      configJson += (char)savedData[i];
    }
  }

  configJson.trim(); // Make sure the string is null-terminated and garbage is removed
  return configJson;
}

void clearROM()
{
  // Loop through all 512 bytes of EEPROM and set each byte to 0xFF
  for (int i = 0; i < 512; i++)
  {
    EEPROM.write(i, 0xFF);
  }
  EEPROM.commit(); // Commit the changes to EEPROM
  Serial.println("EEPROM has been cleared.");
}

void enterConfigurationMode()
{
  clearROM();
  Serial.println("Entering configuration mode...");

  // Collect configuration data
  String wifiSSID = getSerialInput("Enter Wifi-SSID: ", "string");
  String wifiPassword = getSerialInput("Enter Wifi-Password: ", "string");
  String mqttHost = getSerialInput("Enter MQTT HOST: ", "string");
  String mqttPort = getSerialInput("Enter MQTT PORT: ", "integer");
  String mqttUsername = getSerialInput("Enter MQTT USERNAME: ", "string");
  String mqttPassword = getSerialInput("Enter MQTT PASSWORD: ", "string");
  String authToken = getSerialInput("Enter an authorization token in the message: ", "string");
  String mqttTopic = getSerialInput("Enter the MQTT Topic: ", "string");
  String mqttPublishTopic = getSerialInput("Enter the MQTT Publish Topic: ", "string");
  String otaUrl = getSerialInput("Enter the OTA Url (i.e. http://yourhost.com/firmware.bin): ", "string");
  String relayPinNumber = getSerialInput("Enter the Relay PIN number: (number only) ", "integer");

  // Create JSON
  StaticJsonDocument<256> jsonDoc;
  jsonDoc["wifiSSID"] = wifiSSID;
  jsonDoc["wifiPassword"] = wifiPassword;
  jsonDoc["mqttHost"] = mqttHost;
  jsonDoc["mqttPort"] = mqttPort.toInt();
  jsonDoc["mqttUsername"] = mqttUsername;
  jsonDoc["mqttPassword"] = mqttPassword;
  jsonDoc["authToken"] = authToken;
  jsonDoc["mqttTopic"] = mqttTopic;
  jsonDoc["mqttPublishTopic"] = mqttPublishTopic;
  jsonDoc["otaUrl"] = otaUrl;
  jsonDoc["relayPinNumber"] = relayPinNumber.toInt();

  String configJson;
  serializeJson(jsonDoc, configJson);

  // Save to EEPROM
  saveConfigurationToEEPROM(configJson);

  Serial.println("Configuration saved successfully.");
  GetSavedConfigurations(configJson);
}

// Get serial input with validation
String getSerialInput(const String &prompt, const String &validationType, bool encryptData)
{
  String input = "";

  while (true)
  {
    Serial.println(prompt);
    input = ""; // Clear any previous input

    // Wait for user input until a newline character is detected
    while (true)
    {
      if (Serial.available())
      {
        char c = Serial.read(); // Read a single character

        if (c == '\n')
        {
          Serial.println(); // Print a new line after the user presses Enter
          break;            // Exit the loop when Enter is pressed
        }
        else if (c == '\b' || c == 127)
        { // Handle backspace
          if (input.length() > 0)
          {
            input.remove(input.length() - 1); // Remove the last character
            Serial.print("\b \b");
          }
        }
        else if (c >= 32 && c <= 126)
        {                  // Valid printable ASCII range
          input += c;      // Append character to the input string
          Serial.print(c); // Echo the character back to the Serial Monitor
        }
      }
      delay(10); // Small delay to reduce CPU usage
    }

    input.trim(); // Remove leading/trailing spaces

    // Validate the input
    if (validateEntry(input, validationType))
    {
      break; // Exit the outer loop if the input is valid
    }
    else
    {
      Serial.println("\nInvalid input. Please try again.");
    }
  }

  if (encryptData)
  {
    // Encrypt data using AES
    byte encrypted[512] = {0};
    byte inputBytes[512];
    input.getBytes(inputBytes, 512);

    // Apply AES encryption to the byte array
    aes128.encryptBlock(encrypted, inputBytes);

    // Convert encrypted bytes back to a string to save to EEPROM
    String encryptedString = "";
    for (int i = 0; i < 512; i++)
    {
      encryptedString += (char)encrypted[i];
    }
    return encryptedString;
  }

  return input;
}

// Validate user input
bool validateEntry(const String &entry, const String &field)
{
  if (field == "string")
  {
    return entry.length() > 0;
  }
  else if (field == "integer")
  {
    for (char c : entry)
    {
      if (!isdigit(c))
      {
        return false;
      }
    }
    return true;
  }
  return false;
}
