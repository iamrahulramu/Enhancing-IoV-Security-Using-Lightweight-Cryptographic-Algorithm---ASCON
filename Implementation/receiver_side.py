import  numpy as np
import os
from PIL import Image
import datetime
import ssl
import paho.mqtt.client as paho
import time
import ascon

channel_messages = {
    "Topic_Name/key": b"",
    "Topic_Name/nonce": b"",
    "Topic_Name/associateddata": b"",
    "Topic_Name/cipher": b"",
    "Topic_Name/key2": b"",
    "Topic_Name/nonce2": b"",
    "Topic_Name/associateddata2": b"",
    "Topic_Name/cipher2": b""  
}

def on_connect(client, userdata, flags, rc, properties = None):
    print("CONNACK received with code", rc)

def on_subscribe(client, userdata, mid, granted_qos, properties = None):
    print("Subscribed: " + str(mid) + " " + str(granted_qos))

def on_message(client, userdata, message):
    print(f"Message received on topic: {message.topic}, payload length: {len(message.payload)}")
    global channel_messages

    channel = message.topic  # Get the topic of the message
    payload = message.payload

    # Store the message in the respective channel's variable
    if channel in channel_messages:
        channel_messages[channel] = payload

    # Check if all required components are received for the image(s) sent by Sender 1
    if all(channel_messages[key] for key in ["Topic_Name/key", "Topic_Name/nonce", "Topic_Name/associateddata", "Topic_Name/cipher"]):
        print("All components for the image sent by Sender 1 received. Decrypting...")
        decrypt_image("Topic_Name/key", "Topic_Name/nonce", "Topic_Name/associateddata", "Topic_Name/cipher", "Sender 1 Images")
        print("Image sent by Sender 1 successfully decrypted")
       
    # Check if all required components are received for the image(s) sent by Sender 2
    if all(channel_messages[key] for key in ["Topic_Name/key2", "Topic_Name/nonce2", "Topic_Name/associateddata2", "Topic_Name/cipher2"]):
        print("All components for the image sent by Sender 2 received. Decrypting...")
        decrypt_image("Topic_Name/key2", "Topic_Name/nonce2", "Topic_Name/associateddata2", "Topic_Name/cipher2", "Sender 2 Images")
        print("Image sent by Sender 2 successfully decrypted")

def decrypt_image(key_channel, nonce_channel, associateddata_channel, cipher_channel, output_folder):
    key = channel_messages[key_channel]
    nonce = channel_messages[nonce_channel]
    associateddata = channel_messages[associateddata_channel]
    ciphertext = channel_messages[cipher_channel]

    # Check if the output folder exists, if not create it
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    now = datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
    # Generate a unique filename for saving the decrypted image
    output_filename = f"{now}.png"

    # Perform decryption
    decrypted_plaintext = ascon.ascon_decrypt(key, nonce, associateddata, ciphertext, variant = "Ascon-128")

    if decrypted_plaintext is not None:
        # Convert decrypted plaintext to a numpy array
        hex_string = decrypted_plaintext.hex()
        plaintext_decrypt = np.array([int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)], dtype = np.uint8)

        # Calculate the width and height of the image based on the decrypted plaintext size
        width = int(np.sqrt(len(plaintext_decrypt) // 3))
        height = len(plaintext_decrypt) // (3 * width)

        # Reshape array to original image shape
        decrypted_image_array = plaintext_decrypt.reshape([height, width, 3])

        # Convert the decrypted image data back to a PIL Image
        decrypted_image = Image.fromarray(decrypted_image_array)

        # Save the decrypted image
        decrypted_image.save(os.path.join(output_folder, output_filename))

    # Reset channel_messages for next decryption
    channel_messages[key_channel] = b""
    channel_messages[nonce_channel] = b""
    channel_messages[associateddata_channel] = b""
    channel_messages[cipher_channel] = b""

def save_decrypted_image(decrypted_plaintext, filename):
    # Convert decrypted plaintext to a numpy array
    hex_string = decrypted_plaintext.hex()
    plaintext_bytes = bytes.fromhex(hex_string)
    plaintext_array = np.frombuffer(plaintext_bytes, dtype = np.uint8)

    # Calculate the expected shape of the image
    height, width, channels = 148, 147, 3

    # Reshape the plaintext array to match the expected image shape
    plaintext_reshaped = np.reshape(plaintext_array, (height, width, channels))

    # Convert the reshaped plaintext array to a PIL Image
    decrypted_image = Image.fromarray(plaintext_reshaped)

    # Save the decrypted image
    decrypted_image.save(filename)

def main():
    client = paho.Client(callback_api_version = paho.CallbackAPIVersion.VERSION2,
                     client_id = "Enter the username configured for the Receiver",
                     protocol = paho.MQTTv311)

    client.tls_set(tls_version = ssl.PROTOCOL_TLS_CLIENT)
    client.username_pw_set("Enter the username configured for the Receiver", 
                           "Enter the password configured for the Receiver")

    # Assign callbacks BEFORE loop_start
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message

    client.connect("Enter the MQTT Broker address/URL", "Enter the Port value")
    print("Connecting to HiveMQ Cloud...")

    client.loop_start()

    # Subscribe after loop_start to ensure network thread is running
    for channel in channel_messages:
        client.subscribe(channel, qos = 1)

    print("Connection attempt finished.")

    # Keep the script alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        client.loop_stop()
        client.disconnect()


if (__name__ == '__main__'):
    main()