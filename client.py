import socket
import threading
import json
from cryptography.hazmat.primitives.asymmetric import ec  # Importa criptografia assimétrica (ECC)
from cryptography.hazmat.primitives import hashes  # Importa algoritmos de hash (SHA256)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Para derivar a chave simétrica (AES)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Para criptografia simétrica (AES)
from cryptography.hazmat.backends import default_backend  # Backend para a criptografia
from cryptography.exceptions import InvalidSignature  # Exceção para assinatura inválida
from cryptography.hazmat.primitives import serialization  # Para serialização de chaves públicas
import tkinter as tk  # Para a interface gráfica do usuário (GUI)
import os  # Para funções do sistema operacional, como encerramento do programa
from queue import Queue  # Para gerenciar uma fila de mensagens que serão exibidas na GUI

# Definição do servidor e da porta de comunicação
HOST = 'localhost'  # Endereço do servidor
PORT = 65432  # Porta de comunicação

# Função para gerar um par de chaves (privada e pública) usando criptografia assimétrica (ECC)
def gerar_chaves_ecc():
    chave_privada = ec.generate_private_key(ec.SECP384R1(), default_backend())  # Gera a chave privada
    chave_publica = chave_privada.public_key()  # Gera a chave pública correspondente
    return chave_privada, chave_publica

# Função para derivar uma chave simétrica (AES) usando o segredo compartilhado entre cliente e servidor
def derivar_chave_simetrica(chave_privada, chave_publica_remota):
    segredo_compartilhado = chave_privada.exchange(ec.ECDH(), chave_publica_remota)  # Troca de chaves usando ECDH
    return HKDF(
        algorithm=hashes.SHA256(),  # Usa SHA256 para derivar a chave
        length=32,  # Comprimento da chave simétrica (32 bytes para AES-256)
        salt=None,  # Não usa salt
        info=b"chat_e2e"  # Informação extra usada na derivação da chave
    ).derive(segredo_compartilhado)

# Função para criptografar uma mensagem usando AES no modo CFB
def criptografar_mensagem(mensagem, chave_simetrica):
    iv = os.urandom(16)  # Gera um vetor de inicialização (IV) aleatório
    aes_cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv))  # Cria o objeto Cipher com AES
    encryptor = aes_cipher.encryptor()  # Cria o encriptador
    ciphertext = encryptor.update(mensagem.encode()) + encryptor.finalize()  # Criptografa a mensagem
    return iv + ciphertext  # Retorna o IV e a mensagem criptografada

# Função para descriptografar uma mensagem usando AES no modo CFB
def descriptografar_mensagem(dados_criptografados, chave_simetrica):
    iv = dados_criptografados[:16]  # Extrai o IV dos primeiros 16 bytes
    ciphertext = dados_criptografados[16:]  # O restante é a mensagem criptografada
    aes_cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv))  # Cria o objeto Cipher com AES
    decryptor = aes_cipher.decryptor()  # Cria o descriptografador
    return decryptor.update(ciphertext) + decryptor.finalize()  # Descriptografa a mensagem

# Função para assinar uma mensagem com a chave privada do cliente
def assinar_mensagem(mensagem, chave_privada):
    return chave_privada.sign(mensagem, ec.ECDSA(hashes.SHA256()))  # Assina a mensagem com ECDSA e SHA256

# Função para verificar a assinatura de uma mensagem usando a chave pública do servidor
def verificar_assinatura(mensagem, assinatura, chave_publica):
    try:
        chave_publica.verify(assinatura, mensagem, ec.ECDSA(hashes.SHA256()))  # Verifica a assinatura
        return True  # Assinatura válida
    except InvalidSignature:
        return False  # Assinatura inválida

# Classe Cliente, que gerencia as operações do cliente (conexão, envio e recebimento de mensagens)
class Cliente:
    def __init__(self):
        self.fila_gui = Queue()  # Fila para mensagens a serem exibidas na GUI
        self.encerrar_threads = False  # Flag para controlar o encerramento das threads
        self.root = tk.Tk()  # Cria a janela principal da interface gráfica
        self.root.title("Cliente")  # Título da janela
        self.root.geometry("500x400")  # Define o tamanho da janela
        
        # Criação dos widgets da interface gráfica
        self.texto_chat = tk.Text(self.root, height=20, width=60)  # Campo de texto para exibir as mensagens
        self.texto_chat.pack(pady=10)  # Adiciona o campo de texto à interface
        
        self.frame_controles = tk.Frame(self.root)  # Cria o frame para os controles
        self.frame_controles.pack(pady=5)
        
        self.entrada_mensagem = tk.Entry(self.frame_controles, width=50)  # Campo de entrada de mensagem
        self.entrada_mensagem.pack(side=tk.LEFT, padx=5)
        
        # Botões para enviar e encerrar
        self.botao_enviar = tk.Button(self.frame_controles, text="Enviar", width=10)
        self.botao_encerrar = tk.Button(self.frame_controles, text="Encerrar", width=10, 
                                        command=self.encerrar_cliente)  # Comando para encerrar a conexão
        
        self.botao_enviar.pack(side=tk.LEFT, padx=5)
        self.botao_encerrar.pack(side=tk.LEFT, padx=5)
        
        self.conectar_servidor()  # Função para conectar ao servidor
        self.root.mainloop()  # Inicia a interface gráfica

    # Função para atualizar a GUI periodicamente com novas mensagens
    def atualizar_gui_periodicamente(self):
        while not self.fila_gui.empty():
            mensagem = self.fila_gui.get()  # Obtém a próxima mensagem da fila
            self.texto_chat.insert(tk.END, mensagem)  # Exibe a mensagem na interface
            self.texto_chat.yview(tk.END)  # Rolagem automática para o final
        self.root.after(100, self.atualizar_gui_periodicamente)  # Chama a função a cada 100ms

    # Função para conectar o cliente ao servidor
    def conectar_servidor(self):
        try:
            self.chave_privada, self.chave_publica = gerar_chaves_ecc()  # Gera o par de chaves do cliente
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Cria o socket TCP/IP
            self.sock.connect((HOST, PORT))  # Conecta ao servidor na porta definida

            # Envia a chave pública do cliente para o servidor
            self.sock.sendall(self.chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            # Recebe a chave pública do servidor
            self.chave_publica_servidor = serialization.load_pem_public_key(
                self.sock.recv(4096), 
                backend=default_backend()
            )
            
            # Deriva a chave simétrica usando a chave pública do servidor e a chave privada do cliente
            self.chave_simetrica = derivar_chave_simetrica(
                self.chave_privada, 
                self.chave_publica_servidor
            )
            
            self.botao_enviar.config(command=lambda: self.enviar_mensagem())  # Configura o comando do botão para enviar mensagem
            threading.Thread(target=self.receber_mensagens, daemon=True).start()  # Inicia a thread para receber mensagens
            self.atualizar_gui_periodicamente()  # Começa a atualizar a GUI
            
        except Exception as e:
            self.fila_gui.put(f"Erro de conexão: {str(e)}\n")  # Caso ocorra erro, exibe na GUI
    
    # Função para enviar uma mensagem para o servidor
    def enviar_mensagem(self):
        mensagem = self.entrada_mensagem.get()  # Obtém a mensagem do campo de entrada
        if mensagem:
            try:
                # Criptografa a mensagem e gera a assinatura
                dados_criptografados = criptografar_mensagem(mensagem, self.chave_simetrica)
                assinatura = assinar_mensagem(dados_criptografados, self.chave_privada)
                
                # Envia os dados criptografados e a assinatura para o servidor
                self.sock.sendall(json.dumps({
                    "mensagem": dados_criptografados.hex(),
                    "assinatura": assinatura.hex()
                }).encode())
                
                self.fila_gui.put(f"Você: {mensagem}\n")  # Exibe a mensagem na interface
                self.entrada_mensagem.delete(0, tk.END)  # Limpa o campo de entrada
                
            except Exception as e:
                self.fila_gui.put(f"Erro ao enviar: {str(e)}\n")  # Exibe o erro caso aconteça

    # Função para receber mensagens do servidor
    def receber_mensagens(self):
        while not self.encerrar_threads:
            try:
                dados = self.sock.recv(4096)  # Recebe dados do servidor
                if not dados:
                    break  # Se não houver dados, encerra a conexão
                    
                dados = json.loads(dados.decode())  # Converte os dados de volta para o formato JSON
                mensagem_criptografada = bytes.fromhex(dados["mensagem"])  # Converte a mensagem de volta para bytes
                assinatura = bytes.fromhex(dados["assinatura"])  # Converte a assinatura de volta para bytes
                
                # Verifica a assinatura da mensagem recebida
                if verificar_assinatura(mensagem_criptografada, assinatura, self.chave_publica_servidor):
                    mensagem = descriptografar_mensagem(mensagem_criptografada, self.chave_simetrica).decode()  # Descriptografa a mensagem
                    self.fila_gui.put(f"Servidor: {mensagem}\n")  # Exibe a mensagem na interface
                else:
                    self.fila_gui.put("Assinatura inválida!\n")  # Caso a assinatura seja inválida
                    
            except Exception as e:
                if not self.encerrar_threads:
                    self.fila_gui.put(f"Erro na conexão: {str(e)}\n")  # Exibe erro caso ocorra
                break

    # Função para encerrar o cliente e fechar a conexão
    def encerrar_cliente(self):
        self.encerrar_threads = True  # Marca que o cliente deve ser encerrado
        try:
            self.sock.close()  # Fecha a conexão com o servidor
        except:
            pass
        self.root.destroy()  # Fecha a interface gráfica
        os._exit(0)  # Encerra o programa

# Execução do cliente
if __name__ == "__main__":
    Cliente()  # Inicia a aplicação cliente
