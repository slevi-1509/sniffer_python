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
        with open(file_path, 'r') as file:
            data = json.load(file)
    else:
        data = "No devices found!!!"
    return data, 200

@app.route("/log", methods=["GET"])
def getLog():
    file_path = "server_ai.log"
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = file.read()
    else:
        data = "No log entries found!!!"
    return data, 200

@app.route("/devices", methods=["POST"])
def addDevice():
    device = request.get_json()
    ai_response = get_openai_response(device)
    new_device = {
        "timestamp": device.get('timestamp'),
        "src_mac": device.get('src_mac'),
        "src_ip": device.get('src_ip'),
        "vendor": device.get('vendor'),
        "host_name": device.get('host_name'),
        "os": device.get('os'),
        "port_scan_result": device.get('port_scan_result'),
        "ttl": device.get('ttl'),
        "tcp_window_size": device.get('tcp_window_size'),
        "is_IOT": ai_response['is_IOT'],
        "IOT_reasoning": ai_response['reasoning']
    }
    file_path = "devices.json"
    data = {}
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                data = json.load(file)
        with open(file_path, 'w') as file:
            data[new_device['src_mac']] = new_device
            json.dump(data, file, indent=4)
            return jsonify({"message": "Device added successfully", "device": new_device}), 201
    except Exception as e:
        print(f"Error writing to file: {e}")
        with open(log_file_path, 'a') as log_file:
            log_file.write(f"Error writing to file: {e}\n")
        return jsonify({"error": "Failed to add device"}), 500

if __name__ == "__main__":
    log_file_path = "server_ai.log"
    try:
        app.run(host="0.0.0.0", port=5000)
    except Exception as e:
        print(f"Error starting the server: {e}")
        with open(log_file_path, 'a') as log_file:
            log_file.write(f"Error starting the server: {e}\n")
        exit(1)