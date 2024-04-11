import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import pickle
from cryptography.fernet import Fernet
import base64

# Configuraciones del servidor y cifrado
host = '192.168.56.1'  # Actualiza esto según tu entorno
port = 8000
clave_encriptacion = b'DG-cgQo2hRFJCCq4sZlyQWZtPUzTczxoSeG0RmQvaQA='
cipher_suite = Fernet(clave_encriptacion)

def remote_call(method, args=[]):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # Aumentar según sea necesario
            sock.connect((host, port))
            print(f"Conectado al servidor {host}")
            request = pickle.dumps({'method': method, 'args': args})
            sock.sendall(request)
            print(f"Solicitud enviada: {method}")

            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    print("Timeout al recibir datos. Se procederá con los datos recibidos hasta ahora.")
                    break

            if data:
                response = pickle.loads(data)
                print("Respuesta recibida correctamente")
                return response
            else:
                print("No se recibieron datos del servidor.")
                return "Error: No se recibieron datos del servidor."
    except Exception as e:
        print(f"Error inesperado: {e}")
        return f"Error inesperado: {e}"

def autenticar(usuario, contraseña):
    usuario_enc = cipher_suite.encrypt(usuario.encode())
    contraseña_enc = cipher_suite.encrypt(contraseña.encode())
    return remote_call('autenticar', [usuario_enc, contraseña_enc])

def list_files(directory="."):
    return remote_call('list_files', [directory])

def get_file_base64(filepath):
    return remote_call('get_file_base64', [filepath])

def safe_update_file_list(files):
    if files is None or isinstance(files, str) and files.startswith("Error"):
        update_status_bar(files if files else "Error al actualizar la lista de archivos.", "error")
    else:
        file_list.delete(0, tk.END)
        for file in files:
            file_list.insert(tk.END, file)
        update_status_bar("Lista de archivos actualizada con éxito.")

def attempt_update_file_list():
    files = list_files()
    root.after(100, safe_update_file_list, files)

def update_file_list():
    attempt_update_file_list()

def download_file():
    selected_file = file_list.get(tk.ANCHOR)
    if selected_file:
        file_content_base64 = get_file_base64(selected_file)
        if isinstance(file_content_base64, str) and file_content_base64.startswith("Error"):
            update_status_bar(file_content_base64, "error")
        else:
            file_content = base64.b64decode(file_content_base64)
            save_path = filedialog.asksaveasfilename(initialfile=selected_file)
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(file_content)
                update_status_bar("Archivo descargado con éxito.")

def update_status_bar(message, type="success"):
    if type == "error":
        error_status_bar.config(text=message)
    else:
        success_status_bar.config(text=message)

root = tk.Tk()
root.title("Cliente RMI - Gestor de Archivos")

file_list = tk.Listbox(root, width=50, height=15)
file_list.pack(pady=20)

download_button = ttk.Button(root, text="Descargar Archivo Seleccionado", command=download_file)
download_button.pack(pady=10)

error_status_bar = tk.Label(root, text="", fg="red")
error_status_bar.pack(fill=tk.X, side=tk.BOTTOM)

success_status_bar = tk.Label(root, text="", fg="green")
success_status_bar.pack(fill=tk.X, side=tk.BOTTOM)

root.after(100, update_file_list)

root.mainloop()
