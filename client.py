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

class Cliente:
    def __init__(self):
        self.fila_gui = Queue()
        self.encerrar_threads = False
        self.root = tk.Tk()
        self.root.title("Cliente")
        self.root.geometry("500x400")
        
        self.texto_chat = tk.Text(self.root, height=20, width=60)
        self.texto_chat.pack(pady=10)
        
        self.frame_controles = tk.Frame(self.root)
        self.frame_controles.pack(pady=5)
        
        self.entrada_mensagem = tk.Entry(self.frame_controles, width=50)
        self.entrada_mensagem.pack(side=tk.LEFT, padx=5)
        
        self.botao_enviar = tk.Button(self.frame_controles, text="Enviar", width=10)
        self.botao_encerrar = tk.Button(self.frame_controles, text="Encerrar", width=10, 
                                      command=self.encerrar_cliente)
        
        self.botao_enviar.pack(side=tk.LEFT, padx=5)
        self.botao_encerrar.pack(side=tk.LEFT, padx=5)
        
        self.conectar_servidor()
        self.root.mainloop()
    
    def atualizar_gui_periodicamente(self):
        while not self.fila_gui.empty():
            mensagem = self.fila_gui.get()
            self.texto_chat.insert(tk.END, mensagem)
            self.texto_chat.yview(tk.END)
        self.root.after(100, self.atualizar_gui_periodicamente)
    
    def conectar_servidor(self):
        try:
            self.chave_privada, self.chave_publica = gerar_chaves_ecc()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            
            # Handshake
            self.sock.sendall(self.chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            self.chave_publica_servidor = serialization.load_pem_public_key(
                self.sock.recv(4096), 
                backend=default_backend()
            )
            
            self.chave_simetrica = derivar_chave_simetrica(
                self.chave_privada, 
                self.chave_publica_servidor
            )
            
            self.botao_enviar.config(command=lambda: self.enviar_mensagem())
            threading.Thread(target=self.receber_mensagens, daemon=True).start()
            self.atualizar_gui_periodicamente()
            
        except Exception as e:
            self.fila_gui.put(f"Erro de conexão: {str(e)}\n")
    
    def enviar_mensagem(self):
        mensagem = self.entrada_mensagem.get()
        if mensagem:
            try:
                dados_criptografados = criptografar_mensagem(mensagem, self.chave_simetrica)
                assinatura = assinar_mensagem(dados_criptografados, self.chave_privada)
                
                self.sock.sendall(json.dumps({
                    "mensagem": dados_criptografados.hex(),
                    "assinatura": assinatura.hex()
                }).encode())
                
                self.fila_gui.put(f"Você: {mensagem}\n")
                self.entrada_mensagem.delete(0, tk.END)
                
            except Exception as e:
                self.fila_gui.put(f"Erro ao enviar: {str(e)}\n")
    
    def receber_mensagens(self):
        while not self.encerrar_threads:
            try:
                dados = self.sock.recv(4096)
                if not dados:
                    break
                    
                dados = json.loads(dados.decode())
                mensagem_criptografada = bytes.fromhex(dados["mensagem"])
                assinatura = bytes.fromhex(dados["assinatura"])
                
                if verificar_assinatura(mensagem_criptografada, assinatura, self.chave_publica_servidor):
                    mensagem = descriptografar_mensagem(mensagem_criptografada, self.chave_simetrica).decode()
                    self.fila_gui.put(f"Servidor: {mensagem}\n")
                else:
                    self.fila_gui.put("Assinatura inválida!\n")
                    
            except Exception as e:
                if not self.encerrar_threads:
                    self.fila_gui.put(f"Erro na conexão: {str(e)}\n")
                break
    
    def encerrar_cliente(self):
        self.encerrar_threads = True
        try:
            self.sock.close()
        except:
            pass
        self.root.destroy()
        os._exit(0)

if __name__ == "__main__":
    Cliente()
