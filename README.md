# Enhancing IoV Security Using Lightweight Cryptographic Algorithm - ASCON

This project proposes a two‑layer security framework for Internet of Vehicles (IoV) environments that combines a lightweight cryptographic algorithm, ASCON, for securing vehicular communication, with a machine learning‑based Network Intrusion Detection System (NIDS) for securing vehicular networks.

---

## Table of Contents
- [Enhancing IoV Security Using Lightweight Cryptographic Algorithm - ASCON](#enhancing-iov-security-using-lightweight-cryptographic-algorithm---ascon)
  - [Table of Contents](#table-of-contents)
  - [Project Overview](#project-overview)
  - [Hardware Components](#hardware-components)
  - [Software Requirements](#software-requirements)
    - [On Raspberry Pi](#on-raspberry-pi)
    - [On HiveMQ Cloud](#on-hivemq-cloud)
  - [Implementation Steps](#implementation-steps)
  - [Implementation Description](#implementation-description)
    - [Sender Side Implementation](#sender-side-implementation)
    - [Receiver Side Implementation](#receiver-side-implementation)
    - [Machine Learning-Based NIDS Implementation](#machine-learning-based-nids-implementation)
    - [Comparison of Lightweight Cryptographic Algorithms](#comparison-of-lightweight-cryptographic-algorithms)
  - [Future Improvements](#future-improvements)
  - [Acknowledgements](#acknowledgements)
  - [License](#license)

---

## Project Overview
This project presents a comprehensive security framework developed to strengthen the Internet of Vehicles (IoV) ecosystem. The framework addresses two fundamental aspects of IoV security:

- **Vehicular Communication Security:** Implementation of the lightweight cryptographic algorithm, ASCON, to secure data transmission between vehicles and infrastructure.
- **Vehicular Network Security:** Integration of a Network Intrusion Detection System (NIDS) using a machine learning-based ensemble voting classifier to ensure anomaly detection and resilience against cyberattacks.

The proposed approach was validated through encrypted image transmission among multiple Raspberry Pi nodes and a central server, replicating real-world IoV communication scenarios.

---

## Hardware Components
This project was implemented and validated using Raspberry Pi 4 Model B boards, which served as vehicle nodes (senders) for securely transmitting image data. Each Raspberry Pi node performed the following tasks:

- Encryption of raw image data using the ASCON encryption algorithm.
- Transmission of encrypted data to the central receiver node (server) using the MQTT protocol.

Additionally, a camera module can be integrated with the Raspberry Pi board to capture real-time image data and further validate system performance.   

_(**Note:** In this implementation, offline images were used to validate the proposed framework.)_

---

## Software Requirements
To set up and run this project, the following software tools and libraries must be installed:

### On Raspberry Pi
- **Operating System:** Raspberry Pi OS / Raspbian
- **Python Version:** Python 3.x
- **Required Python Libraries:** Install all dependencies using the [requirements.txt](requirements.txt) file
  ```bash
  pip install -r requirements.txt
  ```

### On HiveMQ Cloud
HiveMQ Cloud is used as the MQTT broker to enable secure communication between sender and receiver nodes. The MQTT broker can be configured by following these steps:
- Create a HiveMQ Cloud account and set up a free (serverless) cluster.
- Note down the broker address/URL (e.g., ``xxxxx.s1.eu.hivemq.cloud``) and the corresponding port (e.g., ``8883``).
- Add credentials for senders and receiver nodes by assigning usernames and passwords for each node.
  
---

## Implementation Steps

To run and validate the proposed framework, follow the steps below:
1. Set Up the Sender Nodes
   - On each sender Raspberry Pi node, copy the code from [Implementation/sender_side.py](Implementation/sender_side.py).
   - Replace the placeholder values (such as broker address, port, topic name, username, and password) with your HiveMQ Cloud cluster credentials.
   - Any number of sender nodes can be configured to transmit data to the central server. For demonstration purposes, this project uses two sender nodes.
2. Set up the Receiver Node
   - On the central receiver (server) node, copy the code from [Implementation/receiver_side.py](Implementation/receiver_side.py).
   - Replace the placeholder values with your HiveMQ Cloud cluster credentials.
   - The receiver node can be another Raspberry Pi or a standard computer (since it acts as the central server, it is not constrained by mobility or power limitations).

Upon successful execution, two separate directories will be automatically created on the server device - one corresponding to each sender node. Every time an image is transmitted from a sender, the decrypted images are stored in their respective directories. 

(_**NOTE**: Always execute the receiver-side program before the sender-side programs. This ensures that the MQTT subscriptions are active before the senders begin transmitting data._)

---

## Implementation Description
This section provides a brief description of the source code implemented on the Raspberry Pi boards (sender and receiver nodes) and the machine learning-based NIDS implementation. It also includes a short overview of the files in the [Algorithms](Algorithms/) sub-directory, which contains comparative evaluation scripts for several lightweight cryptographic algorithms (and AES).

### Sender Side Implementation

**Script:** [Implementation/sender_side.py](Implementation/sender_side.py)

The script implemented on sender nodes performs the following actions:
- Continuously monitors a specified local directory for new image files using the ``watchdog`` library.
- Encrypts detected images using the ASCON encryption algorithm.
- Publishes the encrypted data securely to the MQTT broker (HiveMQ Cloud) using ``paho-mqtt``.

**MQTT Setup and Connection**
```python
client = paho.Client(callback_api_version = paho.CallbackAPIVersion.VERSION2,
                     client_id = "Enter the username configured for Sender 2", 
                     protocol = paho.MQTTv311)
client.tls_set(tls_version = ssl.PROTOCOL_TLS_CLIENT)
client.username_pw_set(USER, PASS)
client.connect(BROKER, PORT)
client.loop_start()
```
A secure TLS-encrypted connection is established between the sender and the HiveMQ Cloud broker using MQTT over port ``8883``.

**Image Detection and Encryption**
```python
class NewImageHandler(FileSystemEventHandler):
    def __init__(self, client):
        self.client = client
    
    def on_created(self, event):
        if event.is_directory:
            return
        ext = Path(event.src_path).suffix.lower()
        if ext in {".jpg", ".jpeg", ".png"}:
            send_image(event.src_path, self.client)
```
The ``watchdog`` library monitors the specified folder for new image files. When a new image is detected, the ASCON encryption function (executed via the ``ASCON.demo_aead`` function) is called to generate the encrypted ciphertext, key, nonce, and associated data.

**Encrypted Data Publishing**
```python
client.publish("Topic_Name/key2", payload = parameters['key'], qos = 1)
client.publish("Topic_Name/nonce2", payload = parameters['nonce'], qos = 1)
client.publish("Topic_Name/associateddata2", payload = parameters['associated'], qos = 1)
client.publish("Topic_Name/cipher2", payload = parameters['cipher'], qos = 1)
```
The encrypted components are transmitted to the MQTT broker using _QoS level 1_, ensuring each message is delivered at least once.

### Receiver Side Implementation

**Script:** [Implementation/receiver_side.py](Implementation/receiver_side.py)

The script implemented on the central receiver (server) node  performs the following actions:
- Subscribes to all MQTT topics to which senders publish.
- Receives the ASCON-encrypted image data from multiple sender nodes.
- Decrypts the received data using the ASCON decryption algorithm and reconstructs the original images.

**MQTT Subscription and Message Handling**
```python
client.subscribe("Topic_Name/#", qos = 1)
client.on_message = on_message
client.loop_forever()
```
The receiver subscribes to all topics under ``"Topic_Name/#"`` and triggers the ``on_message()`` callback function when new payloads are received.

**ASCON Decryption and Image Reconstruction**
```python
def decrypt_image(key_channel, nonce_channel, associateddata_channel, cipher_channel, output_folder):
    decrypted_plaintext = ASCON.ascon_decrypt(key, nonce, associateddata, ciphertext, variant = "Ascon-128")
    decrypted_image = Image.fromarray(plaintext_decrypt.reshape([height, width, 3]))
    decrypted_image.save(os.path.join(output_folder, output_filename))
```
After all required encrypted components (``key``, ``nonce``, ``associated_data``, and ``cipher``) are received for each sender, the image is decrypted and saved in a dedicated directory (e.g., ``Sender 1 Images``, ``Sender 2 Images``). This ensures clear separation of data from each sender node.

### Machine Learning-Based NIDS Implementation

**Script:** [NIDS/voting_classifier.ipynb](NIDS/voting_classifier.ipynb)

This notebook implements a machine learning-based NIDS trained on the CICIDS-2017 dataset to secure vehicular communication networks.

**Data Preprocessing**
```python
df = pd.read_csv(r"Enter the path of the CICIDS2017 dataset")
df = df[df['Label'].isin(['BENIGN', 'DoS'])]
df[numeric_features] = (df[numeric_features] - df[numeric_features].min()) / (df[numeric_features].max() - df[numeric_features].min())
df = df.fillna(0)
```
The dataset is filtered to include only the Denial of Service (DoS) attack, which is among the most relevant attack types in IoV environments. The filtered dataset is then normalized and cleaned for training.

**Model Training and Evaluation**
```python
classifiers = [
    ('KNN', KNeighborsClassifier()),
    ('Random Forest', RandomForestClassifier()),
    ('Decision Tree', DecisionTreeClassifier()),
    ('Gradient Boosting', GradientBoostingClassifier()),
    ('XGB', xgb.XGBClassifier()),
    ('Extra Trees', ExtraTreesClassifier())
]
voting_clf = VotingClassifier(estimators = classifiers, voting = 'hard')
voting_clf.fit(X_train, y_train)
```
Several classical machine learning algorithms are trained individually and then combined into a voting classifier for improved performance and reliability.

**Performance Analysis**
```python
print("Accuracy:", accuracy_voting)
print("Precision:", precision_voting)
print("Recall:", recall_voting)
sns.heatmap(cm_voting_percentage, annot = True, fmt = '.2f', cmap = 'Blues')
```
Confusion matrices and learning curves are plotted to visualize classifier performance and stability across training sizes.

(_**NOTE:** The machine learning-based NIDS model was trained, validated and tested on the CICIDS-2017 dataset but not integrated into the real-time MQTT communication framework. However, its strong offline performance suggests it can effectively detect intrusions in real-world vehicular networks._)

### Comparison of Lightweight Cryptographic Algorithms

**Directory:** [Algorithms](Algorithms/)

This folder contains notebooks implementing lightweight cryptographic algorithms - PRESENT, TEA, and ASCON - for image encryption. An image encryption implementation using the AES algorithm is also included as a benchmark for performance comparison against ASCON, even though AES is not considered lighweight.

Each script computes standard image encryption quality metrics such as:
- NPCR (Number of Pixels Change Rate)
- UACI (Unified Average Changing Intensity)
- Mean Deviation
- Mean Squared Error (MSE)
- Peak Signal-to-Noise Ratio (PSNR)
- Entropy

These metrics provide insights into the statistical strength and visual distortion resistance of each algorithm. Users can easily test and compare algorithms by specifying the path of any input image in the script. Relevant encryption files are automatically generated in their respective subfolders (e.g., ``AES Encryption Files/``,``ASCON Encryption Files/``, etc.).

---

## Future Improvements
While the current implementation effectively secures vehicular communication and vehicular networks, several enhancements can further improve its efficiency and scalability:
- **Integration with Real-Time Traffic Data:** Utilise live vehicular data streams to evaluate encryption and intrusion detection performance under realistic IoV conditions.
- **Hardware Optimization:** Implement ASCON and other algorithms on dedicated hardware (e.g., FPGA or ARM-based microcontrollers) to analyze execution speed, energy efficiency, and resource usage.
- **Enhanced NIDS Deployment:** Integrate the machine learning-based NIDS into the MQTT communication framework for real-time intrusion monitoring.

---

## Acknowledgements
This project was a collaborative effort developed between August 2023 and May 2024. Special thanks to my fellow contributors, S. Sai Eshwar and Nivetha Elango, for their valuable contributions, and to our supervisors, Dr. Kaythry Pandurangan and Mrs. Bhuvaneshwari A. J., for their continuous guidance and support.

We also express our sincere gratitude to [Maria Eichlseder](https://github.com/meichlseder) and [Han Wu](https://github.com/wuhanstudio) for their publicly available implementations of the ASCON and PRESENT algorithms, respectively. The scripts [Implementation/ascon.py](Implementation/ascon.py) and [Algorithms/present_image_encryption.ipynb](Algorithms/present_image_encryption.ipynb) in this repository were largely adapted from their work. Implementations of the TEA and AES algorithms in the [Algorithms](Algorithms/) directory were adapted from publicly available educational and open-source references.

---

## License
This project is licensed under the terms specified in the ``LICENSE`` file (MIT License).