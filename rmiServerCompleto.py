import socket
import pickle
import ssl
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import threading
import os
import base64

host = '10.0.2.15'  # Asegúrate de configurar esto según tu entorno
port = 8000
clave_encriptacion = b'DG-cgQo2hRFJCCq4sZlyQWZtPUzTczxoSeG0RmQvaQA='
SHARED_FOLDER = "archivos_compartidos"
os.makedirs(SHARED_FOLDER, exist_ok=True)
client_sessions = {}
session_lock = threading.Lock()
SESSION_TIMEOUT = 5  # minutos

def autenticar(usuario_enc, contraseña_enc):
    cipher_suite = Fernet(clave_encriptacion)
    usuario = cipher_suite.decrypt(usuario_enc).decode()
    contraseña = cipher_suite.decrypt(contraseña_enc).decode()
    if usuario == "usuario123" and contraseña == "contrasenaSegura":
        with session_lock:
            client_sessions[usuario] = datetime.now()
        return True
    return False

def list_files(directory="."):
    try:
        files = os.listdir(os.path.join(SHARED_FOLDER, directory))
        print(f"Enviando lista de archivos: {files}")
        return files
    except Exception as e:
        print(f"Error al listar archivos: {e}")
        return [f"Error al listar archivos: {e}"]

def get_file_base64(filepath):
    try:
        full_path = os.path.join(SHARED_FOLDER, filepath)
        with open(full_path, 'rb') as file:
            return base64.b64encode(file.read()).decode('utf-8')
    except Exception as e:
        return str(e)

def client_connected(client_ip):
    return f"Bienvenido, tu IP es {client_ip}."

def client_disconnected(client_ip):
    return f"Cliente con IP {client_ip} desconectado."

def handle_request(client_socket, addr):
    client_ip = addr[0]
    print(client_connected(client_ip))
    
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            request = pickle.loads(data)
            
            if request['method'] == 'autenticar':
                response = autenticar(request['args'][0], request['args'][1])
            elif request['method'] == 'list_files':
                response = list_files(request['args'][0] if len(request['args']) > 0 else ".")
            elif request['method'] == 'get_file_base64':
                response = get_file_base64(request['args'][0])
            else:
                response = "Método no encontrado."
            client_socket.send(pickle.dumps(response))
    except Exception as e:
        print(f"Error handling request from {client_ip}: {e}")
    finally:
        print(client_disconnected(client_ip))
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Servidor iniciado en {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Conexión desde {addr}")
        threading.Thread(target=handle_request, args=(client_socket, addr)).start()

if __name__ == "__main__":
    start_server()
