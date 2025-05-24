# Gerador e Verificador de Carteiras Bitcoin

Este projeto em Python gera pares de chaves Bitcoin (WIF + endereço), verifica se já foram utilizados e consulta seus saldos via [Blockstream API](https://blockstream.info/api/).

---

### O script irá:

- Carregar o último endereço previamente gerado.

- Gerar novas carteiras únicas a partir do último endereço (Evitando duplicidade com os endereços gerados anteriormente salvos em DataBase/wallets_#.db). A geração de chaves é feita de forma crescente desde o último endereço gerado até o valor definido em WALLET_MAX (dependente também do valor definido em WALLETS_TO_GENERATE).

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

- WALLETS_TO_GENERATE = 1000         # Quantidade total de carteiras únicas a gerar
- API_REQUESTS_PER_SECOND = 2        # Limite de requisições por segundo
- WALLET_MIN                         # Chave minima a ser gerada
- WALLET_MAX                         # Chave maxima a ser gerada

### 3. Execução

- python WalletGenAPI.py