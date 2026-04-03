#include <WiFi.h>
#include <WiFiManager.h>
#include "esp_wifi.h" 
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Math.h>
#include <string.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
  
#define SCK 22
#define SDA 21
#define btn_1 2
#define btn_2 15
#define btn_3 4

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

#define MAX_WIFI 5
#define MAX_BLE 5

String wifiNames[MAX_WIFI];
String bleNames[MAX_BLE];
int bleRSSI[MAX_BLE];
int wifiCount = 0;
int bleCount = 0;

int rryaxis = 6;

int yaxis1 = 16;
int yaxis2 = 16;
int yaxis3 = 16;

int width1 = 57;
int width2 = 75;
int width3 = 96;

int CurrentScreen = 0;

int scanTime = 5;

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

//Wifi Scanner
void scanWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  int count = WiFi.scanNetworks();
  wifiCount = min(count, MAX_WIFI);
  for (int i = 0; i < wifiCount; i++) {
    wifiNames[i] = WiFi.SSID(i);
    if (wifiNames[i].length() > 15) wifiNames[i] = wifiNames[i].substring(0, 15);
  }
}

// BLE Scanner
void scanBLE(int scanTime) {
  BLEScan* scan = BLEDevice::getScan();
  scan->setActiveScan(true);
  BLEScanResults* results = scan->start(scanTime, false);

  bleCount = 0;
  for (int i = 0; i < results->getCount() && bleCount < MAX_BLE; i++) {
    BLEAdvertisedDevice device = results->getDevice(i);
    if (device.haveName()) {
      String name = device.getName().c_str();
      if (name.length() > 12) name = name.substring(0, 12);
      bleNames[bleCount] = name;
      bleRSSI[bleCount] = device.getRSSI();
      bleCount++;
    }
  }
}

// Wifi Packet Analyzer
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t *payload = pkt->payload;

  if ((payload[0] & 0xFC) == 0xC0) {
    display.setTextColor(SSD1306_WHITE);
    Serial.print("Deauth Detected!");
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 20);
    display.println("Deauth Frame, Attack Detected!");
    delay(3000);
  }
}
static bool snifferOn = false;

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  Wire.begin();
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();

  // BTN (Button) Logic
  pinMode(btn_1, INPUT_PULLUP);
  pinMode(btn_2, INPUT_PULLUP);
  pinMode(btn_3, INPUT_PULLUP);

  BLEDevice::init("");
  scanWiFi();
  scanBLE(5);
}

void loop() {
  // put your main code here, to run repeatedly:
display.clearDisplay();

if (CurrentScreen == 0) { 
  //First Icons To Choose From
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(50, 11);
  display.println("WIFI");
  
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(50, 31);
  display.println("BLTH");

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(50, 51);
  display.println("SNIF");

  //Curser For Selecting A Direction
  display.drawRoundRect(45, rryaxis, 32, 16, 40, SSD1306_WHITE);

  //Button 1 Input
  if (digitalRead(btn_1) == LOW) {
    display.drawRoundRect(45, rryaxis, 32, 16, 40, SSD1306_BLACK);
    rryaxis += 20; //moves the y axis down 20 pixels
    delay(200);  //debounce
  }  
  
  // If statement for when the button is pressed
  if (rryaxis > 51) { rryaxis = 6; }

  //Button 2 Inputs
  if (digitalRead(btn_2) == LOW) {
    delay(150);
    if (rryaxis == 6)  { CurrentScreen = 1; }
    if (rryaxis == 26) { CurrentScreen = 2; }
    if (rryaxis == 46) { CurrentScreen = 3; }
    }

}

// Displays Network Connections + RSSI
  if (CurrentScreen == 1) {
    display.clearDisplay();
    display.setCursor(5, 0);
    display.println("Finding Networks...");

    // Establish WIFI Mode and Setup
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

int y = 10;
for (int i = 0; i < wifiCount && i < 6; i++) {
  display.setCursor(0, y);
  display.print(wifiNames[i]);
  display.print(" ");
  display.println(WiFi.RSSI(i));
  y += 10;
}
    }

// Displays BLE Connections + RSSI
  if (CurrentScreen == 2) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Searching Connections...");

    BLEScan* scan = BLEDevice::getScan();
    scan->setActiveScan(true);

    int y = 10;
    for (int i = 0; i < bleCount && i < 6; i++) {
      display.setCursor(0, y);
      display.print(bleNames[i]);
      display.print(" ");
      display.println(bleRSSI[i]);
      y += 10;
    }
}

// Selection Screen For Type of Scans
  if (CurrentScreen == 3) {
      display.setCursor(20,0);
      display.println("Sniffer Menu");
      display.setCursor(5, 20);
      display.println("Deauther Sniff");
      display.setCursor(5, 40);
      display.println("Beacon Spam Sniff");

      display.drawRoundRect(0, yaxis3, width3, 16, 40, SSD1306_WHITE);

       if (digitalRead(btn_1) == LOW) {
           display.drawRoundRect(0, yaxis3, width3, 16, 40, SSD1306_BLACK);
           yaxis3 += 20; //moves the y axis down 20 pixels
           delay(200);  //debounce
           width3 += 17;
           delay(200);

           if (width3 > 120) { width3 = 96; }
           if (yaxis3 > 40) { yaxis3 = 16; }
  }  
      //Button 2 Inputs
  if (digitalRead(btn_2) == LOW) {
    delay(150);
    if (yaxis3 == 16)  { CurrentScreen = 31; }
    if (yaxis3 == 36) { CurrentScreen = 32; }
    }
      }

// Screen 31 Listens for Deauthentication Frames 
if (CurrentScreen == 31) {

  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextColor(SSD1306_WHITE);
    if (!snifferOn) {
      WiFi.mode(WIFI_STA);
      esp_wifi_set_promiscuous_rx_cb(&sniffer);
      esp_wifi_set_promiscuous(true);
      snifferOn = true;
    }
  display.println("Scanning For Attacks");
  WiFi.disconnect();
  }

if (CurrentScreen == 32) {
  display.clearDisplay();
  display.setCursor(5, 0);
  display.println("Scanning For Attacks");

  int count2 = WiFi.scanNetworks();
  display.setCursor(0, 20);
  display.print("SSID's: ");
  display.print(" ");
  display.println(count2);
  
  if (count2 > 40) {
    display.setCursor(0, 10);
    display.setTextColor(SSD1306_WHITE);
    display.print("Possible Beacon Spam!");
  }
}

//Button 3 Input 
// Brings You Back To The Home Screen
if (digitalRead(btn_3) == LOW) { CurrentScreen = 0; }

display.display();
}
