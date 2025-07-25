import socket
import threading

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            print("Port {} is open".format(port))
        elif result == 10013:  # Connection refused
            print("Port {} is open but permission denied".format(port))
        sock.close()
    except:
        pass

def port_scan(host, start_port, end_port):
    for port in range(start_port, end_port+1):
        threading.Thread(target=scan_port, args=(host, port)).start()

if __name__ == '__main__':
    host = 'localhost'
    start_port = 1
    end_port = 1000
    port_scan(host, start_port, end_port)

# import asyncio

# async def scan_port(host, port):
#     try:
#         reader, writer = await asyncio.open_connection(host, port)
#         print("Port {} is open".format(port))
#         writer.close()
#     except:
#         pass

# async def port_scan(host, start_port, end_port):
#     tasks = []
#     for port in range(start_port, end_port+1):
#         tasks.append(scan_port(host, port))
#     await asyncio.gather(*tasks)

# if __name__ == '__main__':
#     host = 'localhost'
#     start_port = 1
#     end_port = 1000
#     asyncio.run(port_scan(host, start_port, end_port))

# import socket

# class ConnectionPool:
#     def __init__(self, host, start_port, end_port):
#         self.host = host
#         self.start_port = start_port
#         self.end_port = end_port
#         self.pool = []
#         self.create_connections()

#     def create_connections(self):
#         for port in range(self.start_port, self.end_port+1):
#             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             sock.settimeout(0.5)
#             self.pool.append((port, sock))

#     def scan_port(self, port):
#         try:
#             port, sock = port
#             sock.connect_ex((self.host, port))
#             print("Port {} is open".format(port))
#             sock.close()
#         except:
#             pass

#     def port_scan(self):
#         for port in self.pool:
#             self.scan_port(port)

# if __name__ == '__main__':
#     host = 'localhost'
#     start_port = 1
#     end_port = 1000
#     pool = ConnectionPool(host, start_port, end_port)
#     pool.port_scan()

# import socket
# import multiprocessing

# def scan_port(host, port):
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(0.5)
#         result = sock.connect_ex((host, port))
#         if result == 0:
#             print("Port {} is open".format(port))
#         sock.close()
#     except:
#         pass

# def port_scan(host, start_port, end_port, num_processes):
#     pool = multiprocessing.Pool(processes=num_processes)
#     for port in range(start_port, end_port+1):
#         pool.apply_async(scan_port, (host, port))
#     pool.close()
#     pool.join()

# if __name__ == '__main__':
#     host = 'localhost'
#     start_port = 1
#     end_port = 1000
#     num_processes = 4
#     port_scan(host, start_port, end_port, num_processes)