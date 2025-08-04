from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
from openai_request import get_openai_response

app = Flask(__name__)
CORS(app)
    
@app.route("/", methods=["GET"])
def getRoot():
    """
    Root endpoint to check if the server is running.
    """
    return "It's ALIVE !!!"

@app.route("/devices", methods=["GET"])
def getDevices():
    file_path = "devices.json"
    if os.path.exists(file_path):
        with open('your_file.json', 'r') as file:
            data = json.load(file)
    else:
        data = "No devices found!!!"
    return data, 200

@app.route("/devices", methods=["POST"])
def addDevice():
    device = request.get_json()
    device = {**device, 'is_IOT': get_openai_response(device)}
    file_path = "devices.json"
    data = {}
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                data = json.load(file)
        with open(file_path, 'w') as file:
            data[device['src_mac']] = device
            json.dump(data, file, indent=4)
            return jsonify({"message": "Device added successfully", "device": device}), 201
    except Exception as e:
        print(f"Error writing to file: {e}")
        return jsonify({"error": "Failed to add device"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)