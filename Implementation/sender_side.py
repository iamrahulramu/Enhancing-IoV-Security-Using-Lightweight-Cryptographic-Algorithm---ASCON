import ssl, time
import numpy as np
from PIL import Image
import paho.mqtt.client as paho
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ascon
import time
from pathlib import Path

BROKER = "Enter the MQTT Broker address/URL"
PORT = "Enter the Port value"
USER = "Enter the username configured for Sender 2"
PASS = "Enter the password configured for Sender 2"

parameters = dict()

def on_connect(client, userdata, flags, rc, properties = None):
    print("CONNACK received:", rc)

def on_publish(client, userdata, mid, reasonCode, properties = None):
    print(f"Message {mid} published, reasonCode = {reasonCode}")

def encryption_parameters():
    with open('Encryption Parameters/key.txt','rb') as f: parameters['key'] = f.read()
    with open('Encryption Parameters/nonce.txt','rb') as f: parameters['nonce'] = f.read()
    with open('Encryption Parameters/associated_data.txt','rb') as f: parameters['associated'] = f.read()
    with open('Encryption Parameters/encrypted_data.txt','rb') as f: parameters['cipher'] = f.read()

def send_image(path, client):
    while True:
        try:
            img = Image.open(path)
            img.verify()
            img = Image.open(path).resize((256, 256))
            break
        except Exception:
            time.sleep(0.5)

    img = Image.open(path).resize((256, 256))
    image_array = np.array(img)
    Path("ASCON Encryption Data").mkdir(parents = True, exist_ok = True)
    ciphertext = ascon.demo_aead("Ascon-128", image_array)
    encryption_parameters()

    client.publish("Topic_Name/key2", payload = parameters['key'], qos = 1)
    client.publish("Topic_Name/nonce2", payload = parameters['nonce'], qos = 1)
    client.publish("Topic_Name/associateddata2", payload = parameters['associated'], qos = 1)
    client.publish("Topic_Name/cipher2", payload = parameters['cipher'], qos = 1)
    print(f"Published encrypted image from: {path}")

class NewImageHandler(FileSystemEventHandler):
    def __init__(self, client):
        self.client = client
    
    def on_created(self, event):
        if event.is_directory:
            return
        ext = Path(event.src_path).suffix.lower()
        if ext in {".jpg", ".jpeg", ".png"}:
            send_image(event.src_path, self.client)

def main():
    client = paho.Client(callback_api_version = paho.CallbackAPIVersion.VERSION2,
                         client_id = "Enter the username configured for Sender 2", protocol = paho.MQTTv311)
    client.on_connect = on_connect
    client.on_publish = on_publish
    client.tls_set(tls_version = ssl.PROTOCOL_TLS_CLIENT)
    client.username_pw_set(USER, PASS)
    client.connect(BROKER, PORT)
    client.loop_start()

    watch_dir = Path(r"Enter the path of the local directory containing images to be transmitted")
    watch_dir.mkdir(exist_ok = True)
    handler = NewImageHandler(client)
    observer = Observer()
    observer.schedule(handler, str(watch_dir), recursive = False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()