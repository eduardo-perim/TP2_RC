import socket
import threading
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import tkinter as tk
import os
from queue import Queue

HOST = 'localhost'
PORT = 65432
MAX_CLIENTES = 10

def gerar_chaves_ecc():
    chave_privada = ec.generate_private_key(ec.SECP384R1(), default_backend())
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica

def derivar_chave_simetrica(chave_privada, chave_publica_remota):
    segredo_compartilhado = chave_privada.exchange(ec.ECDH(), chave_publica_remota)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chat_e2e"
    ).derive(segredo_compartilhado)

def criptografar_mensagem(mensagem, chave_simetrica):
    iv = os.urandom(16)
    aes_cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(mensagem.encode()) + encryptor.finalize()
    return iv + ciphertext

def descriptografar_mensagem(dados_criptografados, chave_simetrica):
    iv = dados_criptografados[:16]
    ciphertext = dados_criptografados[16:]
    aes_cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv))
    decryptor = aes_cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def assinar_mensagem(mensagem, chave_privada):
    return chave_privada.sign(mensagem, ec.ECDSA(hashes.SHA256()))

def verificar_assinatura(mensagem, assinatura, chave_publica):
    try:
        chave_publica.verify(assinatura, mensagem, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

class ClienteHandler:
    def __init__(self, conn, addr, chave_privada_servidor, atualizar_gui):
        self.conn = conn
        self.addr = addr
        self.chave_publica = None
        self.chave_simetrica = None
        self.atualizar_gui = atualizar_gui
        self.chave_privada_servidor = chave_privada_servidor
        self.encerrado = False

    def handshake(self):
        try:
            self.chave_publica = serialization.load_pem_public_key(
                self.conn.recv(4096), 
                backend=default_backend()
            )
            
            self.conn.sendall(
                self.chave_privada_servidor.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            
            self.chave_simetrica = derivar_chave_simetrica(
                self.chave_privada_servidor, 
                self.chave_publica
            )
            
            self.atualizar_gui(f"Cliente {self.addr} conectado. Chave estabelecida!")

        except Exception as e:
            self.atualizar_gui(f"Erro no handshake: {str(e)}")
            self.encerrado = True

    def receber_mensagens(self):
        while not self.encerrado:
            try:
                dados = self.conn.recv(4096)
                if not dados:
                    break
                    
                dados = json.loads(dados.decode())
                mensagem_criptografada = bytes.fromhex(dados["mensagem"])
                assinatura = bytes.fromhex(dados["assinatura"])

                if verificar_assinatura(mensagem_criptografada, assinatura, self.chave_publica):
                    mensagem = descriptografar_mensagem(mensagem_criptografada, self.chave_simetrica).decode()
                    self.atualizar_gui(f"Cliente {self.addr}: {mensagem}")
                else:
                    self.atualizar_gui(f"Assinatura inválida do cliente {self.addr}")

            except Exception as e:
                if not self.encerrado:
                    self.atualizar_gui(f"Erro com cliente {self.addr}: {str(e)}")
                break

        self.encerrar()

    def enviar_mensagem(self, mensagem):
        try:
            dados_criptografados = criptografar_mensagem(mensagem, self.chave_simetrica)
            assinatura = assinar_mensagem(dados_criptografados, self.chave_privada_servidor)
            
            self.conn.sendall(json.dumps({
                "mensagem": dados_criptografados.hex(),
                "assinatura": assinatura.hex()
            }).encode())
            
        except Exception as e:
            self.atualizar_gui(f"Erro ao enviar para {self.addr}: {str(e)}")

    def encerrar(self):
        self.encerrado = True
        try:
            self.conn.close()
        except:
            pass
        self.atualizar_gui(f"Cliente {self.addr} desconectado")

class Servidor:
    def __init__(self):
        self.clientes = []
        self.fila_gui = Queue()
        self.encerrar = False
        self.chave_privada, _ = gerar_chaves_ecc()
        
        self.root = tk.Tk()
        self.root.title("Servidor")
        self.root.geometry("600x500")
        self.root.protocol("WM_DELETE_WINDOW", self.encerrar_servidor)
        
        self.texto_chat = tk.Text(self.root, height=25, width=70)
        self.texto_chat.pack(pady=10)
        
        self.frame_controles = tk.Frame(self.root)
        self.frame_controles.pack(pady=5)
        
        self.entrada_mensagem = tk.Entry(self.frame_controles, width=50)
        self.entrada_mensagem.pack(side=tk.LEFT, padx=5)
        
        self.botao_enviar = tk.Button(self.frame_controles, text="Enviar para Todos", 
                                    command=self.enviar_para_todos)
        self.botao_enviar.pack(side=tk.LEFT, padx=5)
        
        threading.Thread(target=self.iniciar_servidor, daemon=True).start()
        self.atualizar_gui_periodicamente()
        
    def atualizar_gui(self, mensagem):
        self.fila_gui.put(mensagem)
        
    def atualizar_gui_periodicamente(self):
        while not self.fila_gui.empty():
            mensagem = self.fila_gui.get()
            self.texto_chat.insert(tk.END, f" {mensagem}\n")
            self.texto_chat.yview(tk.END)
        self.root.after(100, self.atualizar_gui_periodicamente)
        
    def iniciar_servidor(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(MAX_CLIENTES)
            self.atualizar_gui(f"Servidor iniciado em {HOST}:{PORT}")

            while not self.encerrar:
                try:
                    conn, addr = s.accept()
                    cliente = ClienteHandler(conn, addr, self.chave_privada, self.atualizar_gui)
                    self.clientes.append(cliente)
                    cliente.handshake()
                    threading.Thread(target=cliente.receber_mensagens, daemon=True).start()
                except Exception as e:
                    if not self.encerrar:
                        self.atualizar_gui(f"Erro ao aceitar conexão: {str(e)}")

    def enviar_para_todos(self):
        mensagem = self.entrada_mensagem.get()
        if mensagem:
            for cliente in self.clientes.copy():
                if not cliente.encerrado:
                    cliente.enviar_mensagem(mensagem)
            self.entrada_mensagem.delete(0, tk.END)
            self.texto_chat.insert(tk.END, f"Você (para todos): {mensagem}\n")
            
    def encerrar_servidor(self):
        self.encerrar = True
        for cliente in self.clientes:
            cliente.encerrar()
        self.root.destroy()
        os._exit(0)

if __name__ == "__main__":
    Servidor().root.mainloop()
