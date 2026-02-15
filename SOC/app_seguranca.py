import streamlit as st
import pandas as pd
import plotly.express as px

# Configuração da Página
st.set_page_config(page_title="Security Intelligence", layout="wide")

st.title("🛡️ Dashboard de Análise de Anomalias (MDR)")
st.markdown(f"**Analista Responsável:** Alan Molter")

# 1. Carregamento Vetorizado dos Dados
@st.cache_data # Cache para não recarregar o arquivo a cada clique
def load_data():
    df = pd.read_json('firewall_logs.json')
    # Exemplo de Vetorização: Criando uma coluna de 'Risco Alto' de forma rápida
    df['is_high_risk'] = df['bytes_sent'] > 1000000
    return df

df = load_data()

# 2. Sidebar para Filtros (Interatividade)
st.sidebar.header("Filtros de Investigação")
ip_filter = st.sidebar.multiselect("Selecione IPs Suspeitos:", df['src_ip'].unique())

if ip_filter:
    df = df[df['src_ip'].isin(ip_filter)]

# 3. Métricas Principais (KPIs)
col1, col2, col3 = st.columns(3)
col1.metric("Total de Logs", len(df))
col2.metric("IPs Únicos", df['src_ip'].nunique())
col3.metric("Alertas Críticos", df['is_high_risk'].sum())

# 4. Visualizações Espaciais e Temporais
st.subheader("Análise de Volume de Tráfego")
fig_volume = px.line(df, x='timestamp', y='bytes_sent', color='src_ip', title="Volume de Dados por IP (Exfiltração)")
st.plotly_chart(fig_volume, use_container_width=True)

# 5. Tabela de Investigação com Destaque
st.subheader("Logs brutos para Investigação (Forensics)")
# Usamos estilização para destacar anomalias visualmente
st.dataframe(df.style.highlight_max(axis=0, subset=['bytes_sent'], color='red'))

st.info("Este dashboard utiliza processamento vetorizado para garantir performance em datasets de larga escala.")