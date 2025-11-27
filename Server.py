import requests
import tensorflow as tf
from tensorflow import keras
import numpy as np
import pickle
import math
import pyrebase
import urllib.parse
import time
import json

# Firebase Configuration
config = {
    "apiKey": "AIzaSyAU_OZaGs1i7A1M_aoGvvd_7w9HmDIcHak",
    "authDomain": "safescape-vjec.firebaseapp.com",
    "databaseURL": "https://safescape-vjec-default-rtdb.firebaseio.com",
    "storageBucket": "safescape-vjec.firebasestorage.app"
}

firebase = pyrebase.initialize_app(config)
db = firebase.database()

API_KEY = "AIzaSyCkyOF04xwSNWTuv9vLwUh1Tk-5epM_DVY"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Primary Check Function
def primaryCheck(url):
    try:
        model = keras.models.load_model("MaliciousUrlDetector.h5")
        with open("tokenizer.pkl", "rb") as handle:
            tokenizer = pickle.load(handle)
        with open("label_encoder.pkl", "rb") as handle:
            label_encoder = pickle.load(handle)

        class FeatureExtractor:
            def _init_(self, url=""):
                self.url = url
                self.domain = url.split('//')[-1].split('/')[0]

            def url_entropy(self):
                url_trimmed = self.url.strip()
                entropy_distribution = [float(url_trimmed.count(c)) / len(url_trimmed) for c in dict.fromkeys(list(url_trimmed))]
                return -sum([e * math.log(e, 2) for e in entropy_distribution if e > 0])

            def digits_num(self):
                return len([i for i in self.url if i.isdigit()])

            def length(self):
                return len(self.url)

            def params_num(self):
                return len(self.url.split('&')) - 1

            def fragments_num(self):
                return len(self.url.split('#')) - 1

            def subdomain_num(self):
                return len(self.domain.split('.')) - 1

            def dom_ext(self):
                return self.domain.split('.')[-1]

            def has_http(self):
                return 'http' in self.url

            def has_https(self):
                return 'https' in self.url

            def is_ip(self):
                parts = self.domain.split('.')
                if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                    return True
                return False

            def run(self):
                return {
                    "url": self.url,
                    "entropy": self.url_entropy(),
                    "digits": self.digits_num(),
                    "url_length": self.length(),
                    "param_nums": self.params_num(),
                    "fragment_nums": self.fragments_num(),
                    "subdomain_nums": self.subdomain_num(),
                    "domain_extension": self.dom_ext(),
                    "has_http": self.has_http(),
                    "has_https": self.has_https(),
                    "is_ip": self.is_ip(),
                    "num_%20": self.url.count("%20"),
                    "num_@": self.url.count("@")
                }

        extractor = FeatureExtractor(url)
        url_features = extractor.run()

        sequence = tokenizer.texts_to_sequences([url])
        padded_sequence = tf.keras.preprocessing.sequence.pad_sequences(sequence, maxlen=100, padding='post', truncating='post')

        extra_features = np.array([[url_features['entropy'], url_features['digits'],
                                    url_features['url_length'], url_features['param_nums'],
                                    url_features['has_http'], url_features['has_https'],
                                    url_features['is_ip'], url_features['num_%20'],
                                    url_features['num_@']]]).astype(np.int32)

        prediction = model.predict([padded_sequence, extra_features])
        predicted_class = np.argmax(prediction, axis=1)
        class_labels = label_encoder.inverse_transform(predicted_class)

        if class_labels[0] == 'safe':
            return 0
        else:
            return 1

    except FileNotFoundError:
        return "Error: Model or tokenizer/label encoder files not found."
    except Exception as e:
        return f"An error occurred: {e}"

# Validation Check Function
def validationCheck(url):
    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    params = {"key": API_KEY}
    response = requests.post(SAFE_BROWSING_URL, params=params, json=payload)

    if response.status_code == 200:
        data = response.json()
        if "matches" in data:
            return 1
        return 0
    else:
        print("Error:", response.text)
        return None

# Combined Check Function
def combined_check(url):
    primary_result = primaryCheck(url)
    validation_result = validationCheck(url)

    if validation_result is not None:
        return validation_result
    else:
        return primary_result

# Fetch and Decode URL
def fetch_and_decode_url(path):
    try:
        encoded_url = db.child(path).get().val()
        if encoded_url:
            if isinstance(encoded_url, str) and encoded_url.startswith('"') and encoded_url.endswith('"'):
                encoded_url = json.loads(encoded_url)
            decoded_url = urllib.parse.unquote(encoded_url)
            return decoded_url
        else:
            return None
    except Exception as e:
        print(f"Error fetching/decoding URL: {e}")
        return None

# Combined Firebase Logic with While Loop and User Specific Result
def process_url_from_firebase():
    previous_busy_status = "0"
    while True:
        try:
            current_busy_status = db.child("Server/Busy").get().val()
            if isinstance(current_busy_status, str) and current_busy_status.startswith('"') and current_busy_status.endswith('"'):
                current_busy_status = json.loads(current_busy_status)

            if current_busy_status == "1" and current_busy_status != previous_busy_status:
                username = db.child("Server/Username").get().val()
                if isinstance(username, str) and username.startswith('"') and username.endswith('"'):
                    username = json.loads(username)

                decoded_url = fetch_and_decode_url("Server/Url")
                if decoded_url:
                    encoded_url = urllib.parse.quote(decoded_url, safe=':/')
                    final_result = combined_check(encoded_url)
                    db.child(f"USERS/{username}/Result").set(final_result)
                    db.child("Server/Busy").set(0)
                    db.child("Server/Url").set(0)
                    db.child("Server/Username").set(0)
                    print(f"Processed URL: {decoded_url}, Result: {final_result}, Username: {username}")
                else:
                    print("No URL to process.")
                previous_busy_status = current_busy_status
            elif current_busy_status == "0" and previous_busy_status == "1":
                previous_busy_status = current_busy_status
            time.sleep(1)

        except Exception as e:
            print(f"Error processing Firebase data: {e}")
            time.sleep(1)

# Example Usage
process_url_from_firebase()