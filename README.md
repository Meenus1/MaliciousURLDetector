# Malicious URL Detector – Mobile Application (Machine Learning + Firebase)

This project is a mobile application that detects malicious URLs using a **trained Machine Learning model** and **Google Safe Browsing API**.  
The app communicates with a Python backend via **Firebase Realtime Database** to provide real-time URL safety classification.

---

## 🚀 Features

- Detects malicious URLs using a deep learning model (BiLSTM)
- Real-time URL classification using Firebase
- Secondary verification using Google Safe Browsing API
- Android mobile application (built using Kodular)

---

## 📌 Demo

A short screen recording of the application in use:

➡️ `Demo/screen_recording.mp4`

---

## 📂 Project Structure

MaliciousURLDetector/
│
├── Model/
│ ├── MaliciousUrlDetector.h5
│ ├── tokenizer.pkl
│ └── label_encoder.pkl
│
├── server_code.ipynb # Python backend (Google Colab) for model + Firebase communication
├── requirements.txt
├── README.md
│
└── Demo/
└── screen_recording.mp4


---

## 🛠 Installation & Usage

1️⃣ Clone the repository
  git clone https://github.com/Meenus1/MaliciousURLDetector.git
  cd MaliciousURLDetector

2️⃣ Install dependencies
  pip install -r requirements.txt

3️⃣ Start the backend server (Google Colab recommended)
  Open server_code.ipynb in Google Colab
  Run all cells
  Keep the notebook running while using the app

4️⃣ Use the mobile app
  Install the APK on Android
  Enter a URL → receive the safety result in real-time

---

## 🧠 Model Details
MaliciousUrlDetector.h5	- Trained BiLSTM model to classify URLs
tokenizer.pkl	- Converts input URLs into integer sequences for model input
label_encoder.pkl	- Converts predicted class index → (safe / malicious) label

Training dataset and .ipynb training notebooks are not included due to size and copyright limitations.

---

## 🔥 Firebase Configuration
The backend listens to the following Realtime Database values:

Server/Busy	- Notifies server when a URL is submitted
Server/Url	- Encoded URL sent by mobile app
Server/Username	- Username who initiated the scan
USERS/<username>/Result	- Scan result returned by the backend

---

## 🤝 Contributing
This project is intended for educational and portfolio demonstration.

---