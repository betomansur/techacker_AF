from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alertas')
def alertas():
    # Carregar o DataFrame processado
    try:
        logs = pd.read_csv('logs_processados.csv')
    except FileNotFoundError:
        return "O arquivo 'logs_processados.csv' não foi encontrado. Execute 'processar_logs.py' primeiro."

    # Verificar se o DataFrame não está vazio
    if logs.empty:
        return "Não há dados disponíveis para análise."

    # Filtrar as requisições suspeitas
    alertas_lista = logs[logs['label'] == 1]

    # Verificar se há alertas
    if alertas_lista.empty:
        return "Nenhum alerta foi encontrado."

    # Converter para dicionário para passar para o template
    alertas_lista = alertas_lista.to_dict(orient='records')

    return render_template('alertas.html', alertas=alertas_lista)

if __name__ == '__main__':
    app.run(debug=True)
