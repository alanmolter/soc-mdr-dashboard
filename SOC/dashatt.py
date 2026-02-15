import streamlit as st
import requests
import pandas as pd

# Substitua pela sua chave real ou use st.sidebar.text_input para segurança
API_KEY = "1d6e350e150b143cc4ff455a7e87a571e9f57af826259658d82429fbb8e6df5d" 

# ==============================================================================
# LÓGICA DE CACHE: Otimização de Performance e Custo
# ==============================================================================

# O parâmetro 'ttl=3600' significa Time To Live. 
# O resultado ficará guardado por 1 hora (3600 segundos).
@st.cache_data(ttl=3600)
def get_ip_reputation(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Retorna o número de motores que detectaram o IP como malicioso
            return data['data']['attributes']['last_analysis_stats']['malicious']
        return 0
    except Exception as e:
        return f"Erro: {e}"

# ==============================================================================
# INTERFACE DO DASHBOARD
# ==============================================================================

st.title("🛡️ Investigação de Ameaças - Enriquecimento de Logs")

# Simulando um IP detectado pelo seu Isolation Forest
ip_alvo = st.text_input("IP para Investigação:", "203.0.113.50")

if st.button("Consultar Reputação"):
    with st.spinner('Consultando inteligência de ameaças...'):
        resultado = get_ip_reputation(ip_alvo)
        
        if isinstance(resultado, int):
            if resultado > 0:
                st.error(f"⚠️ O IP {ip_alvo} é considerado MALICIOSO por {resultado} fontes.")
            else:
                st.success(f"✅ O IP {ip_alvo} não possui registros negativos recentes.")
        else:
            st.warning(resultado)

st.caption("Implementado com Cache LRU para otimização de requisições à API externa.")