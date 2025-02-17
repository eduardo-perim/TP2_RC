import socket
import threading
import json
from cryptography.hazmat.primitives.asymmetric import ec  # Importa criptografia assimétrica (ECC)
from cryptography.hazmat.primitives import hashes  # Algoritmos de hash (SHA256)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Para derivar uma chave simétrica
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Para criptografia simétrica AES
from cryptography.hazmat.backends import default_backend  # Backend para a criptografia
from cryptography.exceptions import InvalidSignature  # Exceção para assinatura inválida
from cryptography.hazmat.primitives import serialization  # Para serialização de chaves públicas
import tkinter as tk  # Para interface gráfica
import os  # Para funções do sistema operacional, como geração de números aleatórios
from queue import Queue  # Para gerenciar a fila de mensagens a serem exibidas na interface

# Definições de constantes
HOST = 'localhost'  # Endereço do servidor
PORT = 65432  # Porta do servidor
MAX_CLIENTES = 10  # Máximo de clientes que podem se conectar

# Função para gerar um par de chaves (pública e privada) usando ECC (Elliptic Curve Cryptography)
def gerar_chaves_ecc():
    chave_privada = ec.generate_private_key(ec.SECP384R1(), default_backend())  # Gera chave privada
    chave_publica = chave_privada.public_key()  # Gera chave pública correspondente
    return chave_privada, chave_publica

# Função para derivar uma chave simétrica (AES) compartilhada usando ECDH (Elliptic Curve Diffie-Hellman)
def derivar_chave_simetrica(chave_privada, chave_publica_remota):
    segredo_compartilhado = chave_privada.exchange(ec.ECDH(), chave_publica_remota)  # Gera segredo compartilhado
    return HKDF(
        algorithm=hashes.SHA256(),  # Usa SHA256 para hash
        length=32,  # Comprimento da chave simétrica derivada (32 bytes para AES-256)
        salt=None,  # Nenhum salt é usado
        info=b"chat_e2e"  # Informação adicional para derivação da chave
    ).derive(segredo_compartilhado)

# Função para criptografar uma mensagem usando AES em modo CFB
def criptografar_mensagem(mensagem, chave_simetrica):
    iv = os.urandom(16)  # Gera um vetor de inicialização (IV) aleatório
    aes_cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv))  # Cria o objeto Cipher com AES
    encryptor = aes_cipher.encryptor()  # Cria o encriptador
    ciphertext = encryptor.update(mensagem.encode()) + encryptor.finalize()  # Criptografa a mensagem
    return iv + ciphertext  # Retorna o IV e a mensagem criptografada

# Função para descriptografar uma mensagem usando AES em modo CFB
def descriptografar_mensagem(dados_criptografados, chave_simetrica):
    iv = dados_criptografados[:16]  # O IV está nos primeiros 16 bytes
    ciphertext = dados_criptografados[16:]  # O restante é a mensagem criptografada
    aes_cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv))  # Cria o objeto Cipher com AES
    decryptor = aes_cipher.decryptor()  # Cria o descriptografador
    return decryptor.update(ciphertext) + decryptor.finalize()  # Descriptografa a mensagem

# Função para assinar uma mensagem usando a chave privada do servidor
def assinar_mensagem(mensagem, chave_privada):
    return chave_privada.sign(mensagem, ec.ECDSA(hashes.SHA256()))  # Assina a mensagem com ECDSA e SHA256

# Função para verificar a assinatura de uma mensagem usando a chave pública do servidor
def verificar_assinatura(mensagem, assinatura, chave_publica):
    try:
        chave_publica.verify(assinatura, mensagem, ec.ECDSA(hashes.SHA256()))  # Verifica a assinatura com ECDSA
        return True  # Assinatura válida
    except InvalidSignature:
        return False  # Assinatura inválida

# Classe para gerenciar cada cliente conectado ao servidor
class ClienteHandler:
    def __init__(self, conn, addr, chave_privada_servidor, atualizar_gui):
        self.conn = conn  # Conexão com o cliente
        self.addr = addr  # Endereço do cliente
        self.chave_publica = None  # Inicializa a chave pública como None
        self.chave_simetrica = None  # Inicializa a chave simétrica como None
        self.atualizar_gui = atualizar_gui  # Função para atualizar a GUI
        self.chave_privada_servidor = chave_privada_servidor  # Chave privada do servidor
        self.encerrado = False  # Flag para controlar se a conexão foi encerrada

    # Função para realizar o handshake entre servidor e cliente (troca de chaves)
    def handshake(self):
        try:
            # Recebe a chave pública do cliente
            self.chave_publica = serialization.load_pem_public_key(
                self.conn.recv(4096), 
                backend=default_backend()
            )
            
            # Envia a chave pública do servidor ao cliente
            self.conn.sendall(
                self.chave_privada_servidor.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            
            # Deriva a chave simétrica usando as chaves pública do cliente e privada do servidor
            self.chave_simetrica = derivar_chave_simetrica(
                self.chave_privada_servidor, 
                self.chave_publica
            )
            
            self.atualizar_gui(f"Cliente {self.addr} conectado. Chave estabelecida!")  # Atualiza a GUI

        except Exception as e:
            self.atualizar_gui(f"Erro no handshake: {str(e)}")  # Caso haja erro, atualiza a GUI
            self.encerrado = True  # Marca a conexão como encerrada

    # Função para receber mensagens dos clientes
    def receber_mensagens(self):
        while not self.encerrado:
            try:
                dados = self.conn.recv(4096)  # Recebe dados do cliente
                if not dados:
                    break
                    
                dados = json.loads(dados.decode())  # Decodifica os dados (em formato JSON)
                mensagem_criptografada = bytes.fromhex(dados["mensagem"])  # Converte a mensagem criptografada de hex para bytes
                assinatura = bytes.fromhex(dados["assinatura"])  # Converte a assinatura de hex para bytes

                # Verifica a assinatura da mensagem
                if verificar_assinatura(mensagem_criptografada, assinatura, self.chave_publica):
                    mensagem = descriptografar_mensagem(mensagem_criptografada, self.chave_simetrica).decode()  # Descriptografa a mensagem
                    self.atualizar_gui(f"Cliente {self.addr}: {mensagem}")  # Exibe a mensagem na GUI
                else:
                    self.atualizar_gui(f"Assinatura inválida do cliente {self.addr}")  # Caso a assinatura seja inválida

            except Exception as e:
                if not self.encerrado:
                    self.atualizar_gui(f"Erro com cliente {self.addr}: {str(e)}")  # Exibe erro caso ocorra
                break

        self.encerrar()  # Encerra a conexão

    # Função para enviar uma mensagem para o cliente
    def enviar_mensagem(self, mensagem):
        try:
            # Criptografa e assina a mensagem
            dados_criptografados = criptografar_mensagem(mensagem, self.chave_simetrica)
            assinatura = assinar_mensagem(dados_criptografados, self.chave_privada_servidor)
            
            # Envia os dados criptografados e a assinatura em formato JSON
            self.conn.sendall(json.dumps({
                "mensagem": dados_criptografados.hex(),
                "assinatura": assinatura.hex()
            }).encode())
            
        except Exception as e:
            self.atualizar_gui(f"Erro ao enviar para {self.addr}: {str(e)}")  # Caso ocorra erro ao enviar

    # Função para encerrar a conexão com o cliente
    def encerrar(self):
        self.encerrado = True  # Marca como encerrado
        try:
            self.conn.close()  # Fecha a conexão
        except:
            pass
        self.atualizar_gui(f"Cliente {self.addr} desconectado")  # Atualiza a GUI

# Classe para o servidor
class Servidor:
    def __init__(self):
        self.clientes = []  # Lista de clientes conectados
        self.fila_gui = Queue()  # Fila para gerenciar mensagens da GUI
        self.encerrar = False  # Flag para controle de encerramento
        self.chave_privada, _ = gerar_chaves_ecc()  # Gera a chave privada do servidor
        
        # Configura a interface gráfica do servidor
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
        
        threading.Thread(target=self.iniciar_servidor, daemon=True).start()  # Inicia o servidor em uma thread separada
        self.atualizar_gui_periodicamente()  # Atualiza a GUI periodicamente
        
    # Função para atualizar a GUI com uma nova mensagem
    def atualizar_gui(self, mensagem):
        self.fila_gui.put(mensagem)
        
    # Função para atualizar a GUI periodicamente
    def atualizar_gui_periodicamente(self):
        while not self.fila_gui.empty():
            mensagem = self.fila_gui.get()
            self.texto_chat.insert(tk.END, f" {mensagem}\n")
            self.texto_chat.yview(tk.END)  # Rolagem automática para o final
        self.root.after(100, self.atualizar_gui_periodicamente)
        
    # Função para iniciar o servidor, aceitando conexões de clientes
    def iniciar_servidor(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permite reutilização de endereço
            s.bind((HOST, PORT))  # Associa o socket ao endereço e porta
            s.listen(MAX_CLIENTES)  # Começa a escutar por conexões
            self.atualizar_gui(f"Servidor iniciado em {HOST}:{PORT}")

            while not self.encerrar:
                try:
                    conn, addr = s.accept()  # Aceita uma conexão
                    cliente = ClienteHandler(conn, addr, self.chave_privada, self.atualizar_gui)  # Cria o handler para o cliente
                    self.clientes.append(cliente)
                    cliente.handshake()  # Realiza o handshake
                    threading.Thread(target=cliente.receber_mensagens, daemon=True).start()  # Inicia a thread para receber mensagens
                except Exception as e:
                    if not self.encerrar:
                        self.atualizar_gui(f"Erro ao aceitar conexão: {str(e)}")

    # Função para enviar uma mensagem para todos os clientes
    def enviar_para_todos(self):
        mensagem = self.entrada_mensagem.get()  # Obtém a mensagem do campo de entrada
        if mensagem:
            for cliente in self.clientes.copy():
                if not cliente.encerrado:
                    cliente.enviar_mensagem(mensagem)  # Envia para cada cliente
            self.entrada_mensagem.delete(0, tk.END)  # Limpa o campo de entrada
            self.texto_chat.insert(tk.END, f"Você (para todos): {mensagem}\n")  # Exibe a mensagem na GUI
            
    # Função para encerrar o servidor
    def encerrar_servidor(self):
        self.encerrar = True  # Marca o servidor como encerrado
        for cliente in self.clientes:
            cliente.encerrar()  # Encerra as conexões com os clientes
        self.root.destroy()  # Fecha a janela do servidor
        os._exit(0)  # Encerra o processo

# Execução do servidor
if __name__ == "__main__":
    Servidor().root.mainloop()  # Inicia a interface gráfica do servidor
