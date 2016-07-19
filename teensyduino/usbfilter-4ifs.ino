/*
 * Teensy 3.2 USB composite device with 4 interfaces
 * including a keyboard, a serial input, a mouse, and a joystick
 * This device is designed for usbfilter evaluation
 * Feb 11, 2016
 * root@davejingtian.org
 * http://davejingtian.org
*/

// For the serial
#define HWSERIAL Serial1

// For the keyboard
int count = 0;

void setup() {
  Serial.begin(9600);
  HWSERIAL.begin(38400);
  delay(1000);
  pinMode(0, INPUT_PULLUP);
  pinMode(1, INPUT_PULLUP);
}

void loop() {
  int i;
  int incomingByte;

  // daveti: give dad some time to upload it
  delay(10000);
  
  // daveti: simple keyboard keeping inputing "hello world"
  // Your computer will receive these characters from a USB keyboard.
  Keyboard.println("lsusb -t");
  Keyboard.println("date");
  //Keyboard.println(count);

  // You can also send to the Arduino Serial Monitor
  //Serial.println(count);

  // increment the count
  count = count + 1;

  // typing too rapidly can overwhelm a PC
  delay(5000);

  // daveti: simple serial - echo both
  if (Serial.available() > 0) {
    incomingByte = Serial.read();
    Serial.print("USB received: ");
    Serial.println(incomingByte, DEC);
                HWSERIAL.print("USB received:");
                HWSERIAL.println(incomingByte, DEC);
  }
  if (HWSERIAL.available() > 0) {
    incomingByte = HWSERIAL.read();
    Serial.print("UART received: ");
    Serial.println(incomingByte, DEC);
                HWSERIAL.print("UART received:");
                HWSERIAL.println(incomingByte, DEC);
  }

  // daveti: simple mouse keeping moving around - triangle move
  for (i=0; i<40; i++) {
    Mouse.move(2, -1);
    delay(25);
  }
  for (i=0; i<40; i++) {
    Mouse.move(2, 2);
    delay(25);
  }
  for (i=0; i<40; i++) {
    Mouse.move(-4, -1);
    delay(25);
  }

  // daveti: simple joystick - basics
  // read analog inputs and set X-Y position
  Joystick.X(analogRead(0));
  Joystick.Y(analogRead(1));

  // read the digital inputs and set the buttons
  Joystick.button(1, digitalRead(0));
  Joystick.button(2, digitalRead(1));

  // a brief delay, so this runs 20 times per second
  delay(50);  
}
