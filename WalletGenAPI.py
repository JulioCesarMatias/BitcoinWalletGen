import hashlib
import base58
import multiprocessing
import csv
import time
import os
import asyncio
import aiohttp
import sqlite3
import glob
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import RIPEMD160

# Configuraçõedo inicio da geração de carteiras (baseado nos dados do site: https://btcpuzzle.info)                                                                                               
INITIAL_WALLET = 1614966549158306225845

# Configurações de Carteiras
WALLETS_TO_GENERATE = 100000  # Número total de carteiras únicas a gerar
WALLETS_PER_CHUNK = 1000 # Número de wallets geradas em paralelo, quanto maior o valor, mais rapido. O valor aqui depende da CPU e memória ram disponíveis

# Configurações da API
API_REQUESTS_PER_SECOND = 14  # Requisições por segundo para a API (para evitar bloqueios)

# Configurações de CPU
NUM_WORKERS = multiprocessing.cpu_count() # Número de núcleos da CPU disponivel para usar durante a geração de carteiras

# Configurações de Arquivos
MAX_DATA_BASE_WALLETS = 500000 # Número máximo de carteiras por arquivo de banco de dados
VALID_WALLETS_FILE = 'wallets_with_balance.csv'
DB_FOLDER = "DataBaseAPI"
DB_BASE_NAME = "wallets_"

# Limita a taxa de chamadas de buscas na API.
class RateLimiter:
    def __init__(self):
        self.delay = 1.0 / API_REQUESTS_PER_SECOND
        self.lock = asyncio.Lock()
        self.last_call = 0

    async def wait(self):
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_call
            wait_time = self.delay - elapsed
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self.last_call = time.time()

# Formata o tempo estimado de chegada (ETA) em horas, minutos e segundos.
def format_eta(seconds):
    hrs = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hrs:02}:{mins:02}:{secs:02}"

# Formata o valor para exibição, substituindo vírgulas por pontos e adicionando separadores de milhar.
def replace_value(valor):
    if isinstance(valor, str):
        valor = int(valor.replace(".", "").replace(",", ""))
    return f"{valor:,}".replace(",", ".")

# Retorna o nome do arquivo do banco de dados para um dado índice, dentro da pasta DB_FOLDER.
def get_db_filename(index):
    return os.path.join(DB_FOLDER, f"{DB_BASE_NAME}{index}.db")

# Cria as tabelas wallets e metadata se não existirem.
def initialize_database(db_filename):
    os.makedirs(os.path.dirname(db_filename), exist_ok=True)
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS wallets (
                        wif TEXT PRIMARY KEY,
                        address TEXT UNIQUE
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS metadata (
                        param TEXT PRIMARY KEY,
                        wif TEXT
                      )''')
    conn.commit()
    conn.close()
    print(f"🗄️ Banco de dados '{db_filename}' inicializado/verificado.")

# Conta o número de carteiras em um arquivo de banco de dados específico.
def get_wallet_count_in_db(db_filename):
    if not os.path.exists(db_filename):
        return 0
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM wallets")
        count = cursor.fetchone()[0]
    except sqlite3.Error:
        count = 0
    conn.close()
    return count

# Insere um lote de carteiras no banco de dados especificado.
def insert_wallets_in_db(db_filename, wallets_batch):
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    try:
        cursor.executemany('INSERT INTO wallets (wif, address) VALUES (?, ?)', wallets_batch)
        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"\n⚠️ Erro de integridade ao inserir em {db_filename}: {e}. Algumas carteiras podem não ter sido inseridas ou já existiam.")
    finally:
        conn.close()

# Remove uma carteira específica do banco de dados pelo WIF.
def delete_wallet_from_db(db_filename, wif):
    conn = None
    try:
        conn = sqlite3.connect(db_filename)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM wallets WHERE wif = ?", (wif,))
        conn.commit()
        if cursor.rowcount > 0:
            pass 
    except sqlite3.Error as e:
        print(f"\n❌ Erro ao excluir carteira {wif} de {db_filename}: {e}")
    finally:
        if conn:
            conn.close()

# Armazena um par param-wif na tabela de metadados.
def store_metadata_in_db(db_filename, param, wif):
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO metadata (param, wif) VALUES (?, ?)", (param, wif))
    conn.commit()
    conn.close()

# Recupera um valor da tabela de metadados.
def get_metadata_from_db(db_filename, param):
    if not os.path.exists(db_filename):
        return None
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT wif FROM metadata WHERE param = ?", (param,))
        row = cursor.fetchone()
    except sqlite3.Error:
        row = None
    conn.close()
    return row[0] if row else None

# Encontra o índice do último banco de dados e o último WIF armazenado nele, dentro da pasta DB_FOLDER.
def find_latest_db_index_and_last_wif():
    os.makedirs(DB_FOLDER, exist_ok=True)
    db_files_pattern = os.path.join(DB_FOLDER, f"{DB_BASE_NAME}*[0-9].db")
    db_files = glob.glob(db_files_pattern)
    if not db_files:
        return 0, None
    max_idx = 0
    for f_path in db_files:
        try:
            filename = os.path.basename(f_path)
            num_str = filename.replace(f"{DB_BASE_NAME}", "").replace(".db", "")
            idx = int(num_str)
            if idx > max_idx:
                max_idx = idx
        except ValueError:
            continue
    if max_idx == 0:
        # Tenta verificar se existe um 'wallets_0.db' ou similar que não foi pego pelo glob
        latest_db_filename_for_idx_0 = get_db_filename(0)
        if os.path.exists(latest_db_filename_for_idx_0):
            retrieved_wif_idx_0 = get_metadata_from_db(latest_db_filename_for_idx_0, 'last_wif')
            # Se encontrou um WIF no banco de dados 0, retorna 0 e o WIF.
            if retrieved_wif_idx_0:
                 return 0, retrieved_wif_idx_0
        return 0, None # Nenhum banco de dados numerado encontrado ou banco de dados 0 não tem WIF.

    latest_db_filename = get_db_filename(max_idx)
    retrieved_wif = get_metadata_from_db(latest_db_filename, 'last_wif')
    return max_idx, retrieved_wif

# Converte uma string WIF (chave comprimida) de volta para a chave privada inteira.
def wif_to_private_key_int(wif_str):
    decoded_wif = base58.b58decode(wif_str)

    if len(decoded_wif) != 38:
        raise ValueError(f"Comprimento WIF inválido para chave comprimida: {len(decoded_wif)}")
    
    version_byte = decoded_wif[0:1]
    key_plus_comp_flag = decoded_wif[1:-4]
    checksum_from_wif = decoded_wif[-4:]

    if version_byte != b'\x80':
        raise ValueError("Byte de versão WIF inválido.")
    
    calculated_checksum = hashlib.sha256(hashlib.sha256(version_byte + key_plus_comp_flag).digest()).digest()[:4]

    if checksum_from_wif != calculated_checksum:
        raise ValueError("Checksum WIF inválido.")
    
    if key_plus_comp_flag[-1:] != b'\x01':
        raise ValueError("Flag de compressão WIF ausente ou inválida.")
    
    private_key_bytes = key_plus_comp_flag[:-1]
    
    return int.from_bytes(private_key_bytes, 'big')

def private_key_to_compressed_wif(private_key_int):
    key_bytes = private_key_int.to_bytes(32, 'big')
    data = b'\x80' + key_bytes + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58.b58encode(data + checksum).decode('ascii')

def private_key_to_compressed_public_key(private_key_int):
    sk = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

def public_key_to_bitcoin_address(public_key):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hasher = RIPEMD160.new()
    ripemd160_hasher.update(sha256_hash)
    pubkey_hash = ripemd160_hasher.digest()
    prefixed = b'\x00' + pubkey_hash
    checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
    return base58.b58encode(prefixed + checksum).decode('ascii')

def generate_wallet_from_key(private_key_int):
    wif = private_key_to_compressed_wif(private_key_int)
    pubkey = private_key_to_compressed_public_key(private_key_int)
    address = public_key_to_bitcoin_address(pubkey)
    return wif, address

# Verifica o saldo e exclui do banco de dados se não houver saldo no endereço.
async def check_balance(session, limiter, wif, address, db_filename, progress_info):
    url = f"https://blockstream.info/api/address/{address}"
    wallet_data_to_return = None
    try:
        await limiter.wait()
        async with session.get(url, timeout=10) as resp:
            if resp.status == 429:
                print(f"\n⏳ API Rate Limit atingido para {address}")
            elif resp.status == 200:
                data = await resp.json()
                # Checa se o endereço tem balanço
                address_balance = data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']
                # Checa se o endereço tem transações
                address_transactions = data['chain_stats']['tx_count']
                if address_balance != 0 or address_transactions > 0:
                    print(f"\n✔ SALDO ENCONTRADO! {address}: {address_balance / 1e8:.8f} BTC")
                    wallet_data_to_return = (wif, address, address_balance / 1e8)
                else: # Saldo é zero ou o número de transações é zero
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, delete_wallet_from_db, db_filename, wif)
            else: # Outros erros HTTP
                print(f"\n❌ Erro HTTP {resp.status} ao consultar saldo para: {address}")
    except asyncio.TimeoutError:
        print(f"\n✘ Timeout ao consultar saldo para: {address}")
    except Exception as e:
        print(f"\n✘ Erro ao consultar saldo para {address}: {repr(e)}")
    finally:
        progress_info["count"] += 1
        if progress_info["count"] > 0 and progress_info["total"] > 0:
            avg_time = (time.time() - progress_info["start"]) / progress_info["count"]
            eta_seconds = avg_time * (progress_info["total"] - progress_info["count"])
            print(f"🔎 Verificando saldo: {replace_value(progress_info['count'])}/{replace_value(progress_info['total'])} | Tempo Estimado: {format_eta(eta_seconds)}           ", end='\r', flush=True)
    return wallet_data_to_return

# Verifica o saldo de uma lista de tuplas (wif, address, db_filename).
async def verify_wallets_balance(wallets_to_check_with_db):
    limiter = RateLimiter()
    progress_info = {"count": 0, "total": len(wallets_to_check_with_db), "start": time.time()}
    wallets_with_balance = []
    if not wallets_to_check_with_db:
        return wallets_with_balance
    async with aiohttp.ClientSession() as session:
        tasks = []
        for wif, addr, db_fn in wallets_to_check_with_db:
            tasks.append(check_balance(session, limiter, wif, addr, db_fn, progress_info))
        results = await asyncio.gather(*tasks)
    print() 
    for r in results:
        if r: # Somente adiciona se check_balance retornou dados (ou seja, tem saldo)
            wallets_with_balance.append(r)
    return wallets_with_balance

def export_wallets_with_balance_to_csv(wallets_data, filename):
    if os.path.dirname(filename) and not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
    file_exists = os.path.isfile(filename)
    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['WIF', 'Address', 'Balance_BTC'])
        for wif, address, balance in wallets_data:
            writer.writerow([wif, address, f"{balance:.8f}"])

def check_existing_wallets_for_balance():
    wallets_to_check = []

    # Verifica todos os bancos de dados no diretório
    for filename in os.listdir(DB_FOLDER):
        if filename.startswith("wallets_") and filename.endswith(".db"):
            db_filename = os.path.join(DB_FOLDER, filename)
            try:
                conn = sqlite3.connect(db_filename)
                cursor = conn.cursor()
                cursor.execute("SELECT wif, address FROM wallets")
                rows = cursor.fetchall()
                for wif, address in rows:
                    wallets_to_check.append((wif, address, db_filename))
                conn.close()
            except Exception as e:
                print(f"❌ Erro ao ler {filename}: {e}")

    if not wallets_to_check:
        return

    print(f"🔍 Encontradas {replace_value(len(wallets_to_check))} carteiras pendentes de verificação de saldo no banco de dados. Verificando saldo via API...")

    found_wallets_with_balance = asyncio.run(verify_wallets_balance(wallets_to_check))

    if found_wallets_with_balance:
        export_wallets_with_balance_to_csv(found_wallets_with_balance, os.path.join(DB_FOLDER, VALID_WALLETS_FILE))

def main():
    global WALLETS_TO_GENERATE
    os.makedirs(DB_FOLDER, exist_ok=True)
    
    # Checa se existem carteiras geradas com pendência de verificação de saldo
    check_existing_wallets_for_balance()

    latest_db_idx, last_saved_wif = find_latest_db_index_and_last_wif()
    current_key_int = INITIAL_WALLET

    # Ajuste para current_db_idx: se latest_db_idx é 0 (ex: wallets_0.db é o último), current_db_idx deve ser 0.
    # Se nenhum banco de dados for encontrado (latest_db_idx=0, last_saved_wif=None), então começamos com 1.
    current_db_idx = latest_db_idx 
    
    last_saved_pk_int = 0

    # Se o último WIF salvo não for None, converta-o para a chave privada inteira
    if last_saved_wif:
        last_saved_pk_int = wif_to_private_key_int(last_saved_wif)
    
    # Se INITIAL_WALLET for maior que o último WIF salvo no banco de dados, reinicie a geração de carteiras a partir de INITIAL_WALLET
    if current_key_int < last_saved_pk_int:
        try:
            current_key_int = last_saved_pk_int + 1
            print(f"↪️ Retomando a partir da chave WIF: {last_saved_wif} (Decimal: {last_saved_pk_int}) no DataBase:{current_db_idx}")
        except ValueError as e:
            print(f"⚠️ Erro ao converter WIF salvo '{last_saved_wif}': {e}. Iniciando do começo ({INITIAL_WALLET}).")
            last_saved_wif = None
            current_key_int = INITIAL_WALLET
            current_db_idx = 1 # Redefinir para 1 se estiver iniciando do zero devido a um erro WIF
    else:
        print(f"🌱 Iniciando do começo do range ({INITIAL_WALLET}).")
        current_db_idx = 1 # Comece com banco de dados 1 se não houver dados anteriores
    
    if WALLETS_TO_GENERATE == 0:
        print("ℹ️ Nenhuma carteira a ser gerada nesta execução.")
        return

    current_db_filename = get_db_filename(current_db_idx)
    initialize_database(current_db_filename)

    if get_wallet_count_in_db(current_db_filename) >= MAX_DATA_BASE_WALLETS:
        print(f"ℹ️ Banco de dados {current_db_filename} está cheio. Avançando para o próximo.")
        current_db_idx += 1
        current_db_filename = get_db_filename(current_db_idx)
        initialize_database(current_db_filename)
    
    print(f"⚙️ Gerando {replace_value(WALLETS_TO_GENERATE)} carteiras únicas com {NUM_WORKERS} núcleos da CPU.")

    wallets_generated_for_balance_check = [] # Lista de (wif, address, db_filename)
    wallets_generated_this_run_count = 0
    wallets_batch_for_db_insert = [] # Lote para inserção no banco de dados atual
    start_time_generation = time.time()

    # Define um tamanho de chunk para processamento em paralelo e escrita no banco de dados
    # Isso ajuda a controlar o uso de memória e a frequência de escritas no banco de dados.
    # Pode ser ajustado conforme necessário.
    PROCESSING_CHUNK_SIZE = NUM_WORKERS * WALLETS_PER_CHUNK

    with multiprocessing.Pool(NUM_WORKERS) as pool:
        while wallets_generated_this_run_count < WALLETS_TO_GENERATE:
            keys_left_in_range = current_key_int + 1
            wallets_needed_for_target = WALLETS_TO_GENERATE - wallets_generated_this_run_count
            
            num_keys_to_process_in_chunk = min(wallets_needed_for_target, PROCESSING_CHUNK_SIZE, keys_left_in_range)
            if num_keys_to_process_in_chunk == 0: break

            private_keys_chunk = list(range(current_key_int, current_key_int + num_keys_to_process_in_chunk))
            
            # Gera carteiras (WIF, Endereço) em paralelo
            generated_wallets_in_chunk = pool.map(generate_wallet_from_key, private_keys_chunk)

            current_key_int += num_keys_to_process_in_chunk
            wallets_generated_this_run_count += len(generated_wallets_in_chunk)

            wallets_batch_for_db_insert.extend(generated_wallets_in_chunk)

            # Verifica se o banco de dados atual está cheio ou se o lote de inserção atingiu um tamanho razoável
            # Ou se terminamos de gerar o necessário
            db_wallet_count = get_wallet_count_in_db(current_db_filename)
            force_write = (wallets_generated_this_run_count == WALLETS_TO_GENERATE)

            if (db_wallet_count + len(wallets_batch_for_db_insert) >= MAX_DATA_BASE_WALLETS or # Banco de dados cheio
                force_write or # Força a escrita se atingimos o número total de carteiras a gerar
                len(wallets_batch_for_db_insert) >= 10000): # Grava no banco de dados a cada 10 mil carteiras geradas
                if wallets_batch_for_db_insert:
                    # Calcula quantas carteiras podemos realmente adicionar a este banco de dados
                    can_add_to_current_db = MAX_DATA_BASE_WALLETS - db_wallet_count
                    to_insert_now = wallets_batch_for_db_insert[:can_add_to_current_db]
                    remaining_for_next_db = wallets_batch_for_db_insert[can_add_to_current_db:]

                    if to_insert_now:
                        insert_wallets_in_db(current_db_filename, to_insert_now)
                        last_wif_in_batch = to_insert_now[-1][0]
                        store_metadata_in_db(current_db_filename, 'last_wif', last_wif_in_batch)
                        for wif, addr in to_insert_now:
                            wallets_generated_for_balance_check.append((wif, addr, current_db_filename))
                    
                    wallets_batch_for_db_insert = remaining_for_next_db

                    if get_wallet_count_in_db(current_db_filename) >= MAX_DATA_BASE_WALLETS or force_write and wallets_batch_for_db_insert:
                        # Se o banco de dados atual está cheio e ainda temos carteiras, ou se forçamos a escrita e ainda há carteiras (porque o banco de dados encheu)
                        # Avança para o próximo banco de dados
                        current_db_idx += 1
                        current_db_filename = get_db_filename(current_db_idx)
                        initialize_database(current_db_filename)
                        print(f"ℹ️ Avançando para novo banco de dados: {current_db_filename}")
                        # Qualquer carteira restante em wallets_batch_for_db_insert será processada na próxima iteração ou no final.
            
            # Atualiza o progresso da geração
            if wallets_generated_this_run_count > 0:
                eta_gen_seconds = ((time.time() - start_time_generation) / wallets_generated_this_run_count) * (WALLETS_TO_GENERATE - wallets_generated_this_run_count)
                print(f"⏳ Gerando carteiras: {replace_value(wallets_generated_this_run_count)}/{replace_value(WALLETS_TO_GENERATE)} | Tempo Estimado: {format_eta(eta_gen_seconds)}           ", end='\r', flush=True)

    # Processar qualquer sobra em wallets_batch_for_db_insert
    while wallets_batch_for_db_insert:
        db_wallet_count = get_wallet_count_in_db(current_db_filename)
        can_add_to_current_db = MAX_DATA_BASE_WALLETS - db_wallet_count
        to_insert_now = wallets_batch_for_db_insert[:can_add_to_current_db]
        remaining_for_next_db = wallets_batch_for_db_insert[can_add_to_current_db:]

        if to_insert_now:
            insert_wallets_in_db(current_db_filename, to_insert_now)
            last_wif_in_batch = to_insert_now[-1][0]
            store_metadata_in_db(current_db_filename, 'last_wif', last_wif_in_batch)
            for wif, addr in to_insert_now:
                wallets_generated_for_balance_check.append((wif, addr, current_db_filename))
        
        wallets_batch_for_db_insert = remaining_for_next_db
        if wallets_batch_for_db_insert: # Se ainda sobraram carteiras, precisa aloca-las em um novo banco de dados
            current_db_idx += 1
            current_db_filename = get_db_filename(current_db_idx)
            initialize_database(current_db_filename)
            print(f"\nℹ️ Avançando para novo banco de dados para restante: {current_db_filename}")

    if wallets_generated_for_balance_check:
        print(f"\n🔎 Iniciando a verificação do saldo de {replace_value(len(wallets_generated_for_balance_check))} carteiras via API...")
        found_wallets_with_balance = asyncio.run(verify_wallets_balance(wallets_generated_for_balance_check))
        if found_wallets_with_balance:
            export_wallets_with_balance_to_csv(found_wallets_with_balance, os.path.join(DB_FOLDER, VALID_WALLETS_FILE))
        else:
            print("ℹ️ Nenhuma carteira com saldo positivo encontrada para exportar.")
    else:
        print("ℹ️ Nenhuma carteira foi gerada para verificação de saldo.")

    print("\n✅ Processo Concluído")

if __name__ == '__main__':
    # Adiciona proteção para multiprocessing em Windows/macOS
    multiprocessing.freeze_support() 
    main()