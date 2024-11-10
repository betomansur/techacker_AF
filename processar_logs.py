import pandas as pd
import numpy as np
import re

# Definir o caminho para o arquivo de log
log_file = r'C:\xampp\apache\logs\access.log'

# Expressão regular para o formato do log
log_pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)" "([^"]*)"'

# Função para analisar cada linha do log
def parse_log_line(line):
    match = re.match(log_pattern, line)
    if match:
        return match.groups()
    else:
        return None

# Ler o arquivo de log e aplicar a função de parsing
with open(log_file, 'r', encoding='utf-8') as f:
    lines = f.readlines()

parsed_lines = [parse_log_line(line) for line in lines]
parsed_lines = [line for line in parsed_lines if line is not None]

# Definir as colunas
colunas = ['ip', 'identd', 'user', 'time', 'request', 'status', 'size', 'referer', 'user_agent', 'cookie']

# Criar o DataFrame
logs = pd.DataFrame(parsed_lines, columns=colunas)

# Verificar se o DataFrame não está vazio
if logs.empty:
    print("O DataFrame está vazio. Verifique se o arquivo de log tem entradas e se o formato está correto.")
    exit()

# Substituir '-' por NaN e converter tipos de dados
logs.replace('-', np.nan, inplace=True)
logs.dropna(subset=['status', 'size', 'time'], inplace=True)

logs['status'] = pd.to_numeric(logs['status'], errors='coerce')
logs['size'] = pd.to_numeric(logs['size'], errors='coerce')

# Limpar e converter a coluna 'time' para datetime
logs['time'] = pd.to_datetime(logs['time'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')

# Remover linhas com 'time' inválido
logs.dropna(subset=['time'], inplace=True)

# Verificar se o DataFrame ainda tem dados
if logs.empty:
    print("Nenhum dado disponível após pré-processamento.")
    exit()

# Remover outliers na coluna 'size' somente se houver dados suficientes
if len(logs) > 10:
    logs = logs[(np.abs((logs['size'] - logs['size'].mean()) / logs['size'].std()) < 3)]
    if logs.empty:
        print("Todos os dados foram removidos como outliers.")
        exit()
else:
    print("Dados insuficientes para remover outliers. Pulando esta etapa.")

# Função para contar o número de parâmetros na requisição
def contar_parametros(request):
    try:
        if '?' in request:
            params = request.split('?')[1].split(' ')[0]
            return len(params.split('&'))
        else:
            return 0
    except:
        return 0

logs['num_params'] = logs['request'].apply(contar_parametros)

# Função para detectar padrões suspeitos nas URLs
def detectar_padroes_suspeitos(request):
    padroes = [
        'select', 'union', 'insert', 'drop', 'update', '<script>', r'\.\./', '%00',
        'OR 1=1', '--', 'sleep', 'benchmark', 'concat', 'load_file', 'outfile'
    ]
    for padrao in padroes:
        if re.search(padrao, request, re.IGNORECASE):
            return 1
    return 0

logs['suspicious_pattern'] = logs['request'].apply(detectar_padroes_suspeitos)

# Função para identificar bots através do User-Agent
def is_bot(user_agent):
    bots = ['bot', 'spider', 'crawler', 'python-requests', 'wget', 'curl']
    if pd.isna(user_agent):
        return 0
    for bot in bots:
        if bot in user_agent.lower():
            return 1
    return 0

logs['is_bot'] = logs['user_agent'].apply(is_bot)

# Classificação baseada em regras simples
def classificar_requisicao(row):
    if row['suspicious_pattern'] == 1:
        return 1  # Suspeito
    elif row['num_params'] > 5:
        return 1  # Suspeito
    elif row['is_bot'] == 1:
        return 1  # Suspeito
    else:
        return 0  # Normal

logs['label'] = logs.apply(classificar_requisicao, axis=1)

# Contagem de requisições suspeitas
total_requisicoes = len(logs)
requisicoes_suspeitas = logs[logs['label'] == 1]
total_suspeitas = len(requisicoes_suspeitas)

print(f"Total de requisições: {total_requisicoes}")
print(f"Total de requisições suspeitas: {total_suspeitas}")
print("Detalhes das requisições suspeitas:")
print(requisicoes_suspeitas[['ip', 'time', 'request', 'user_agent']])

# Opcional: salvar o DataFrame processado
logs.to_csv('logs_processados.csv', index=False)
