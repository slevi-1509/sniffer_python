import { useEffect, useState } from 'react'
import Slider from '@mui/material/Slider'
import axios from 'axios'
import './App.css'

export const App = () => {
  const SERVER_URL = 'http://localhost:5001'
  const [interfaces, setInterfaces] = useState([]);
  const [devices, setDevices] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [parameters, setParameters] = useState({});
  const [portsScan, setPortsScan] = useState(true);
  const [osDetect, setOsDetect] = useState(false);
  const [iotProbability, setIotProbability] = useState(50)

  useEffect (() => {
    const getInfo = async () => {
      try {
        let { data: interfaces } = await axios.get(`${SERVER_URL}/api/interfaces`);
        setInterfaces(interfaces.filter(item => item.ip !== ""));
        setParameters({'interface': interfaces[0]['interface'],
                          'interval': 0,
                          'no_of_packets': 10,
                          'no_of_sessions': 1,
                          'collect_data_time': 3600,
                          'ports_scan': true,
                          'os_detect': false});
        await axios.get(`${SERVER_URL}/api/devices`).then(({ data: response }) => {
          setDevices(response);
        }).catch((error) => {
          console.log(error.message);
        });
        await axios.get(`${SERVER_URL}/api/anomalies`).then(({ data: response }) => {
          if (typeof(response) == String)
            setAnomalies([]);
          setAnomalies(response);
        }).catch((error) => {
          console.log(error.message);
        });
      } catch (error) {
        console.log(error.message);
      }
    }
    getInfo();
  }, [])

  const handleSelect = (e) => {
    let { value, name } = e.target;
    // debugger;
    if (['interval', 'no_of_packets', 'no_of_sessions', 'collect_data_time'].includes(name)) {
      value = parseInt(value);
    }
    setParameters({...parameters, [name]: value})
    console.log(parameters)
  }

  const handleChecked = (e) => {
    let { checked, name } = e.target;
    switch (name) {
      case 'ports_scan':
        setPortsScan(checked);
        break;
      case 'os_detect':
        setOsDetect(checked);
        break;
      default:
        break;
    }
    setParameters({...parameters, [name]: checked})
    console.log(parameters)
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    // let send_params = {'interface': parameters.interface? parameters.interface : interfaces[0]['interface'],
    //                     'interval': parseInt(parameters.interval)? parseInt(parameters.interval) : 0,
    //                     'no_of_packets': parseInt(parameters.no_of_packets)? parseInt(parameters.no_of_packets) : 10,
    //                     'no_of_sessions': parseInt(parameters.no_of_sessions)? parseInt(parameters.no_of_sessions) : 1}
    // console.log(send_params);
    parameters['iot_probability'] = iotProbability;
    try {
      let response = await axios.post(`${SERVER_URL}/api/runsniffer`, JSON.stringify(parameters), {
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } catch (error) {
      console.log(error.message);
    }
  }

  const handle_device_click = async (device) => {
    let device_anomalies = [];
    let { src_mac, src_ip } = device;
    for (let anomaly of anomalies) {
      console.log(anomaly.replace(/'/g, '"'));
      let obj = JSON.parse(anomaly.replace(/'/g, '"'));
      if (obj.src_mac === src_mac) {
        device_anomalies.push(obj);
      }
    console.log(device_anomalies);
    }
  }
  
  return (
    <>
    
      {interfaces && 
        <div>
          <section style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
            <h3>Interface List</h3>
            <label htmlFor="interface">Select an interface:</label>
            <select name="interface" id="interface" onChange={handleSelect}>
              {interfaces.map((interface_item, index) => (
                <option key={index} value={`${interface_item['interface']}`}>{`${index}: ${interface_item['interface']} - ${interface_item['ip']}`}</option>
              ))}
            </select>
          </section>

          <section style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
            <h3>Options:</h3>
            <label htmlFor="interval">Set interval (seconds): </label>
            <input type="number" id="interval" name="interval" defaultValue='0' min="0" onChange={handleSelect} />
            <label htmlFor="no_of_packets">Set number of packets: </label>
            <input type="number" id="no_of_packets" name="no_of_packets" defaultValue='10' min="1" onChange={handleSelect} />
            <label htmlFor="no_of_sessions">Set number of sessions (0 for infinite): </label>
            <input type="number" id="no_of_sessions" name="no_of_sessions" defaultValue='1' min="1" onChange={handleSelect} />
            <label htmlFor="collect_data_time">Set collection data time for anomalies (seconds): </label>
            <input type="number" id="collect_data_time" name="collect_data_time" defaultValue='3600' min="600" onChange={handleSelect} />
            <label><input type="checkbox" name="ports_scan" checked={portsScan} onChange={handleChecked} /> Ports Scanning</label>
            <label><input type="checkbox" name="os_detect" checked={osDetect} onChange={handleChecked} /> Deep OS detection (slower)</label>
            <div className="slidecontainer" style={{width: "10rem"}}>
                <label htmlFor="iot-probability" style={{fontSize: '0.9rem'}}>Minimum IoT Probability: {iotProbability}</label>
                <Slider 
                    id="iot-probability"
                    min={0}
                    max={100}
                    step={1}
                    aria-label="IOT Probability"
                    value={iotProbability}
                    valueLabelDisplay="auto"
                    onChange={(e)=>setIotProbability(e.target.value)} 
                />
                
            </div>
            <br />
            <input type="submit" value="Submit" onClick={handleSubmit} />
          </section>
         
          <div
            style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
            <h3>Devices:</h3>
            {devices && devices.length > 0 ? (
              <table style={{fontSize: '14px', width: '100%', borderCollapse: 'collapse'}}>
                <thead>
                  <tr>
                    <th>Mac</th>
                    <th>IP</th>
                    <th>OS</th>
                    <th>Vendor</th>
                    <th>Hostname</th>
                    <th>is IoT</th>
                  </tr>
                </thead>
                <tbody>
                {devices.map((device, index) => (
                  <tr key={index} onClick={() => handle_device_click(device)}>
                    <td>{device.src_mac}</td>
                    <td>{device.src_ip}</td>
                    <td>{device.os}</td>
                    <td>{device.vendor}</td>
                    <td>{device.host_name}</td>
                    <td>{device.is_IOT}</td>
                  </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p>No devices found.</p>
            )}
        
            <h3>Anomalies:</h3>
            {anomalies && anomalies.length > 0 ? (
              <div>
                {anomalies.map((anomaly, index) => (
                  <div key={index}>
                  <p style={{'border': '1px solid red'}}>{anomaly}</p>
                  </div>
                ))}

              </div>
            ) : (
              <p>No anomalies found.</p>
            )}
          </div>
        </div>      }
    </>
  )
}
