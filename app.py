from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alertas')
def alertas():
    try:
        logs = pd.read_csv('logs_processados.csv')
    except FileNotFoundError:
        return "O arquivo 'logs_processados.csv' não foi encontrado. Execute 'processar_logs.py' primeiro."

    if logs.empty:
        return "Não há dados disponíveis para análise."

    alertas_lista = logs[logs['label'] == 1]

    if alertas_lista.empty:
        return "Nenhum alerta foi encontrado."

    alertas_lista = alertas_lista.to_dict(orient='records')

    return render_template('alertas.html', alertas=alertas_lista)

if __name__ == '__main__':
    app.run(debug=True)
