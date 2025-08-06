from openai import OpenAI
from dotenv import dotenv_values

def get_openai_response(pack_sum):
    
    try:
        
        device_info = {
            "ip": pack_sum['src_ip'],
            "mac": pack_sum['src_mac'],
            "vendor": pack_sum['vendor'],
            "hostname": pack_sum['host_name'],
            "port_scan_result": pack_sum['port_scan_result'],
            "os": pack_sum['os'],
            "dst_mac": pack_sum['dst_mac'],
            "dst_ip": pack_sum['dst_ip'],
            "dst_port": pack_sum['dst_port'],
            "src_port": pack_sum['src_port'],  
            "ttl": pack_sum['ttl'],
            "tcp_window_size": pack_sum['tcp_window_size'],
            "observed_traffic": [
                
            ]
        }
    except Exception as e:
        print(f"Error in device information format: {e}")
        return "Error in device information format"

    # Format device info into prompt
    prompt = f"""
    Given the following device information from a local network, determine if it is likely an IoT device:

    Device Info:
    - IP: {device_info['ip']}
    - MAC: {device_info['mac']}
    - Vendor: {device_info['vendor']}
    - Hostname: {device_info['hostname']}
    - Detected Operating System: {device_info['os']}
    - Destination MAC Address: {device_info['dst_mac']}
    - Destination IP Address: {device_info['dst_ip']}
    - Destination Port: {device_info['dst_port']}
    - Source Port: {device_info['src_port']}
    - TTL: {device_info['ttl']}
    - TCP Window Size: {device_info['tcp_window_size']}
    - Ports and Services with scan status: {device_info['port_scan_result']}
    - Observed Network Behavior: {', '.join(device_info['observed_traffic'])}

    Is this device likely an IoT device?
    return a percentage number of probability that it is an IoT device and a short explanation of the reasoning behind the classification (separated by ::).
    """
    env = dotenv_values('.env')
    client = OpenAI(
        api_key=env.get('OPEN_AI_KEY'),
    )
    
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
    except Exception as e:
        log_file_path = "server_ai.log"
        with open(log_file_path, 'a') as log_file:
            log_file.write(f"OpenAI API error: {e}\n")
        print(f"OpenAI API error: {e}")
        return "Error in OpenAI API request"
    
    res1 = (response.choices[0].message.content.split('::')[0].strip())
    res2 = (response.choices[0].message.content.split('::')[1].strip())
    return {"is_IOT": res1, "reasoning": res2}