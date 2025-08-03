# Gerador e Verificador de Carteiras Bitcoin

Este projeto em Python gera pares de chaves Bitcoin (WIF + endereço), verifica se já foram utilizados e consulta seus saldos via [Blockstream API](https://blockstream.info/api/).

Esse algoritimo não serve e não é utilizado para roubar carteiras (até por que é impossivel pelo tamanho dos números decimais das carteiras, levaria milhares de anos para realizar esse feito, o que prova a segurança do Bitcoin), ele é usado apenas como um algoritimo de força bruta para descobrir as carteiras do desafio de Puzzle`s de Bitcon do site: https://btcpuzzle.info/pt/puzzle, onde o site disponibiliza o range em que a carteira se encontra para fazer a varredura (ponto inicial e final).

---

### O script irá:

- Carregar o último endereço previamente gerado.

- Gerar novas carteiras únicas a partir do último endereço (Evitando duplicidade com os endereços gerados anteriormente salvos em DataBase/wallets_#.db). A geração de chaves é feita de forma crescente desde o último endereço gerado até o valor definido em WALLETS_TO_GENERATE.

- Exportar as chaves geradas para o banco de dados.

- Consultar o saldo das carteiras.

- Salvar os endereços com saldo em wallets_with_balance.csv.

---

## Requisitos

- Python 3.8 ou superior
- pip3 (gerenciador de pacotes Python)

---

## Instalação

Clone o repositório ou salve o código em um arquivo `.py`, por exemplo: `WalletGenAPI.py`.

### 1.  Instale as dependências:

- pip3 install aiohttp ecdsa base58 pycryptodome sqlite3

### 2. Configuração:

- WALLETS_TO_GENERATE         # Quantidade total de carteiras únicas para serem geradas
- API_REQUESTS_PER_SECOND     # Limite de requisições por segundo feitas na API
- INITIAL_WALLET              # Chave minima a ser gerada (Ponto de partida)

### 3. Execução

- python WalletGenAPI.py