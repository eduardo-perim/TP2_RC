# Servidor de Chat com Suporte a Criptografia

## Descrição
A ideia é criar um Socket TCP com chat em tempo real entre um Servidor e Clientes. Haverá duas camadas de criptagrafia para proteger o conteúdo das mensagens enviadas e recebidas. O chat será colocado em prática com o auxílio de uma interface gráfica para a troca de mensagens.

---

## Tecnologias Utilizadas

- **Linguagem de Programação:** Python
- **Bibliotecas** 
  - socket
  - threading
  - json
  - os
  - cryptography
  - tkinter

---

## Como Executar

### Requisitos

- Instalar uma versão moderna de Python
- Instalar a Biblioteca cryptography
- Instalar a Biblioteca Tkinter

### Instruções de Execução

1. **Clone o repositório:**
   ```bash
   git clone <https://github.com/eduardo-perim/TP2_RC.git>
2. **Instale as dependências:**
    ```bash
    pip install cryptography
    sudo apt-get install python3-tk
3. **Execute o servidor:**
    ```bash
    python3 server.py
4. **Execute o cliente:**
    ```bash
    python3 client.py

### Como Testar

 Digite as mensagens que deseja na interface gráfica e elas serão criptografadas, assinadas e enviadas ao clicar no botão "Enviar". As mensagens recebidas serão verificadas, descriptografadas e impressas na tela de interface do chat. Para interromper a conexão de servidor ou cliente, basta clicar no botão "x" da interface referente a ele.

### Funcionalidades Implementadas

 - Criar um Socket TCP
 - Criar um Servidor
 - Criar um Cliente
 - Criptografar mensagens com ECDH
 - Assinar mensagens com ECDSA
 - Enviar mensagens pelo Socket
 - Receber mensagens pelo Socket
 - Verificar assinatura de mensagens com ECDSA
 - Descriptografar mensagens com ECDH
 - Encerrar Servidor
 - Encerrar Cliente
 

### Possíveis Melhorias Futuras

 Criar uma interface mais rebuscada, testar outros tipos de criptografia e adicionar uma possível interação entre clientes (um cliente escolhe mandar a mensagem não apenas ao servidor, mas também para outro cliente específico)
