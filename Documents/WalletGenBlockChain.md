# Configurando o Bitcoin Core para Consulta de Saldos com `bitcoin-cli`

Este guia descreve como configurar o Bitcoin Core para permitir a consulta eficiente de saldos de endereços Bitcoin arbitrários usando a ferramenta de linha de comando `bitcoin-cli`. Esta configuração é essencial para scripts ou aplicações que precisam verificar saldos diretamente da sua cópia local da blockchain.

## Pré-requisitos

*   **Bitcoin Core Instalado**: Você deve ter o Bitcoin Core instalado e sincronizado (ou em processo de sincronização) com a rede Bitcoin.
*   **Acesso à Linha de Comando**: Você precisa ter acesso ao terminal ou prompt de comando no sistema onde o Bitcoin Core está rodando.

## Passos de Configuração

1.  **Localize o Arquivo `bitcoin.conf`**:
    O arquivo de configuração do Bitcoin Core, chamado `bitcoin.conf`, geralmente está localizado no diretório de dados do Bitcoin. Os locais padrão são:
    *   **Windows**: `%APPDATA%\Bitcoin\bitcoin.conf`
    *   **Linux**: `~/.bitcoin/bitcoin.conf`
    *   **macOS**: `~/Library/Application Support/Bitcoin/bitcoin.conf`

    Se o arquivo não existir, você pode criá-lo.

2.  **Habilite o Índice de Transações (`txindex`)**:
    Para consultar saldos de endereços arbitrários (que não pertencem à sua carteira local), você precisa habilitar o índice de transações. Adicione ou modifique a seguinte linha no seu arquivo `bitcoin.conf`:

    ```
    txindex=1
    ```

    **O que `txindex=1` faz?** Esta opção instrui o Bitcoin Core a manter um índice de todas as transações na blockchain. Com este índice, o software pode rapidamente encontrar transações relacionadas a qualquer endereço, não apenas os da sua carteira. Sem `txindex=1`, consultas a endereços arbitrários são muito lentas ou impossíveis.

3.  **Reinicie o Bitcoin Core (e Reindexe se Necessário)**:
    *   Se você adicionou ou alterou `txindex=1` **após** o Bitcoin Core já ter sincronizado parte ou toda a blockchain, você precisará reiniciar o Bitcoin Core com a flag `-reindex` (ou `-reindex-chainstate` para versões mais recentes, que é mais rápido se o `txindex` estava previamente desabilitado). Isso fará com que o Bitcoin Core reconstrua seus bancos de dados para incluir o índice de transações. Este processo pode levar várias horas, dependendo da velocidade do seu computador e do tamanho da blockchain.
        *   Exemplo no Linux/macOS: `bitcoind -reindex`
        *   Exemplo no Windows: `bitcoin-qt.exe -reindex` (ou `bitcoind.exe -reindex`)
    *   Se você está configurando `txindex=1` antes de sincronizar a blockchain pela primeira vez, uma simples reinicialização do Bitcoin Core é suficiente. O índice será construído durante o processo de sincronização inicial.

4.  **Configure o Acesso RPC (Opcional, mas recomendado para `bitcoin-cli`)**:
    Para que o `bitcoin-cli` funcione, o servidor Bitcoin Core precisa estar em execução e aceitando comandos RPC. Geralmente, as configurações padrão são suficientes para uso local. Se você precisar configurar um usuário e senha para RPC (por exemplo, para acesso remoto ou por segurança), adicione ao `bitcoin.conf`:

    ```
    rpcuser=seu_usuario_rpc
    rpcpassword=sua_senha_rpc_super_segura
    ```
    Lembre-se de escolher um usuário e uma senha fortes. Se você definir `rpcuser` e `rpcpassword`, o `bitcoin-cli` precisará dessas credenciais, que podem ser passadas como argumentos ou configuradas em um arquivo de configuração para `bitcoin-cli`.
    Para uso local do script na mesma máquina, muitas vezes o Bitcoin Core permite acesso RPC sem senha se certas condições de segurança forem atendidas (por exemplo, permissões de arquivo do cookie RPC). Para simplificar, o script pode assumir que `bitcoin-cli` já está configurado para funcionar sem precisar passar credenciais explicitamente a cada comando.

5.  **Verifique se `bitcoin-cli` está Funcionando**:
    Após reiniciar o Bitcoin Core (e esperar a reindexação, se aplicável), abra um novo terminal e teste se o `bitcoin-cli` pode se comunicar com o servidor Bitcoin Core. Um comando simples para testar é:

    ```bash
    bitcoin-cli getblockchaininfo
    ```

    Se este comando retornar informações sobre a blockchain, seu `bitcoin-cli` está funcionando.

## Verificando a Configuração para Consulta de Saldos

Para confirmar que o `txindex=1` está ativo e funcionando, você pode tentar consultar um endereço arbitrário (que não está na sua carteira) usando o comando `scantxoutset`. Por exemplo:

```bash
bitcoin-cli scantxoutset start '["addr(1BitcoinEaterAddressDontSendf59kuE)"]'
```

Se o comando retornar informações sobre UTXOs (mesmo que seja um saldo zero para um endereço válido), o `txindex` provavelmente está funcionando. Se você receber um erro indicando que a consulta não é possível sem `txindex`, verifique sua configuração e o status da reindexação.

## Notas Adicionais

*   **Espaço em Disco**: Habilitar `txindex=1` aumentará significativamente o espaço em disco necessário para armazenar os dados da blockchain (geralmente um adicional de 15-30% ou mais sobre o tamanho da blockchain já sincronizada).
*   **Tempo de Sincronização/Reindexação**: A sincronização inicial ou o processo de reindexação com `txindex=1` será mais demorado.
*   **Segurança**: Se você configurar `rpcuser` e `rpcpassword`, proteja seu arquivo `bitcoin.conf` e escolha senhas fortes.

Seguindo estes passos, seu nó Bitcoin Core estará pronto para que o script Python consulte saldos de endereços Bitcoin diretamente da sua cópia local da blockchain.
