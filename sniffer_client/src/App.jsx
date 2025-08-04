import { useEffect, useState } from 'react'
import axios from 'axios'
import './App.css'

export const App = () => {
  const SERVER_URL = 'http://localhost:5001'
  const [interfaces, setInterfaces] = useState([]);
  const [devices, setDevices] = useState({});
  const [parameters, setParameters] = useState({});

  useEffect (() => {
    const getInfo = async () => {
      try {
        let { data: interfaces } = await axios.get(`${SERVER_URL}/api/interfaces`);
        setInterfaces(interfaces.filter(item => item.ip !== ""));
        let { data: devices } = await axios.get(`${SERVER_URL}/api/devices`);
        console.log(Object.values(devices));
        setDevices(Object.values(devices));
      } catch (error) {
        console.log(error.message);
      }
    }
    getInfo();
  }, [])

  const handleSelect = (e) => {
    let { value, name } = e.target;
    setParameters({...parameters, [name]: value})
    console.log(parameters)
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    let send_params = {'interface': parameters.interface? parameters.interface : interfaces[0]['interface'],
                        'interval': parseInt(parameters.interval)? parseInt(parameters.interval) : 0,
                        'no_of_packets': parseInt(parameters.no_of_packets)? parseInt(parameters.no_of_packets) : 10,
                        'no_of_sessions': parseInt(parameters.no_of_sessions)? parseInt(parameters.no_of_sessions) : 1}
    console.log(send_params);
    try {
      let response = await axios.post(`${SERVER_URL}/api/runsniffer`, JSON.stringify(send_params), {
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } catch (error) {
      console.log(error.message);
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
            <input type="number" id="interval" name="interval" defaultValue='0' onChange={handleSelect} />
            <label htmlFor="no_of_packets">Set number of packets: </label>
            <input type="number" id="no_of_packets" name="no_of_packets" defaultValue='10' onChange={handleSelect} />
            <label htmlFor="no_of_sessions (0 for infinite)">Set number of sessions (0 for infinite): </label>
            <input type="number" id="no_of_sessions" name="no_of_sessions" defaultValue='1' onChange={handleSelect} />
            <label><input type="checkbox" name="ports_scan" defaultChecked={true} onChange={handleSelect} /> Ports Scanning</label>
            <label><input type="checkbox" name="os_detect" defaultChecked={false} onChange={handleSelect} /> Deep OS detection (slower)</label>
            <br />
            <input type="submit" value="Submit" onClick={handleSubmit} />
          </section>
         
          <div
            style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
            <h3>Devices:</h3>
            {devices.length > 0 ? (
              <table>
                <thead>
                  <tr>
                    <th>Mac</th>
                    <th>IP</th>
                    <th>OS</th>
                    <th>Vendor</th>
                    <th>Hostname</th>
                  </tr>
                </thead>
                <tbody>
                {devices.map((device, index) => (
                  <tr key={index}>
                    <td>{device.src_mac}</td>
                    <td>{device.src_ip}</td>
                    <td>{device.os}</td>
                    <td>{device.vendor}</td>
                    <td>{device.host_name}</td>
                  </tr>
                  ))}
                </tbody>
              </table>
              
            ) : (
              <p>No devices found.</p>
            )}
          </div>
        </div>
      }
    </>
  )
}
