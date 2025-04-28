import pandas as pd
import requests
import gzip
import shutil
from datetime import datetime

# Mapear mudanças de versão do EPSS
VERSOES_EPSS = {
    "2022-02-04": "v2",
    "2023-03-07": "v3",
    "2025-03-17": "v4"
}

def detectar_versao(data_str):
    """Detecta a versão do EPSS baseada na data"""
    data = datetime.strptime(data_str, "%Y-%m-%d")
    if data >= datetime(2025, 3, 17):
        return "v4"
    elif data >= datetime(2023, 3, 7):
        return "v3"
    elif data >= datetime(2022, 2, 4):
        return "v2"
    else:
        return "v1"

def validar_datas(data1, data2):
    """Valida se a primeira data é anterior à segunda"""
    d1 = datetime.strptime(data1, "%Y-%m-%d")
    d2 = datetime.strptime(data2, "%Y-%m-%d")
    return d1 < d2

def baixar_e_extrair(data):
    """Baixa e extrai o arquivo CSV de uma data"""
    url = f"https://epss.empiricalsecurity.com/epss_scores-{data}.csv.gz"
    gz_file = f"epss_scores-{data}.csv.gz"
    csv_file = f"{data}.csv"

    print(f"Baixando {url} ...")
    response = requests.get(url)
    if response.status_code == 200:
        with open(gz_file, 'wb') as f:
            f.write(response.content)
        print(f"Arquivo {gz_file} baixado. Extraindo...")
        with gzip.open(gz_file, 'rb') as f_in:
            with open(csv_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"Arquivo {csv_file} extraído.")
    else:
        print(f"Erro ao baixar o arquivo para {data}. Código HTTP: {response.status_code}")
        exit()

# Entrada do usuário
data1 = input("Digite a primeira data (formato YYYY-MM-DD): ")
data2 = input("Digite a segunda data (formato YYYY-MM-DD): ")

# Validação de datas
if not validar_datas(data1, data2):
    print("Erro: a primeira data deve ser ANTERIOR à segunda. Tente novamente.")
    exit()

# Verificar versões EPSS
versao1 = detectar_versao(data1)
versao2 = detectar_versao(data2)

if versao1 != versao2:
    print(f"Atenção: você está comparando {versao1} → {versao2}. A mudança de modelo EPSS pode causar grandes variações de score!\n")

# Quantidade de CVEs que o usuário quer ver
try:
    quantidade = int(input("Quantos CVEs com aumento de EPSS você quer visualizar? "))
except ValueError:
    print("Erro: Digite um número inteiro válido.")
    exit()

# Baixar e extrair arquivos
baixar_e_extrair(data1)
baixar_e_extrair(data2)

# Carregar datasets
epss_1 = pd.read_csv(f"{data1}.csv", comment='#')
epss_2 = pd.read_csv(f"{data2}.csv", comment='#')

# Manter apenas CVE ID e EPSS Score
epss_1 = epss_1[['cve', 'epss']]
epss_2 = epss_2[['cve', 'epss']]

# Juntar datasets
merged = pd.merge(epss_1, epss_2, on='cve', suffixes=('_inicio', '_fim'))

# Calcular diferença
merged['epss_shift'] = merged['epss_fim'] - merged['epss_inicio']

# Filtrar apenas aumentos
aumentos = merged[merged['epss_shift'] > 0]

# Ajustar se pediu mais CVEs do que existem
if quantidade > len(aumentos):
    print(f"\nSó existem {len(aumentos)} CVEs que aumentaram. Mostrando todos.\n")
    quantidade = len(aumentos)

# Ordenar pelos que mais subiram
aumentos = aumentos.sort_values('epss_shift', ascending=False).head(quantidade)

# Mostrar resultados numerados
print(f"\n--- Top {quantidade} CVEs que MAIS AUMENTARAM o EPSS de {data1} para {data2} ---")
for i, (_, row) in enumerate(aumentos.iterrows(), start=1):
    print(f"{i}. {row['cve']} | EPSS início: {row['epss_inicio']:.4f} | EPSS fim: {row['epss_fim']:.4f} | Aumento: +{row['epss_shift']:.4f}")
