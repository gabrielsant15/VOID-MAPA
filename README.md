# 🌐 VOID MAP — Live Threat Intelligence Dashboard

Painel interativo de monitoramento de ciberameaças em tempo real construído 100% em **Python**, inspirado em centros de operações de segurança (SOC) modernos.

## 🚀 Modos de Operação

O **VOID MAP** conta com 3 fontes de dados selecionáveis direto na interface:

1. **Feed Público Real (Sem API Key):** Coleta endereços IP maliciosos reais e recentes de listas abertas da comunidade (*Blocklist.de*) e realiza geolocalização em tempo real.
2. **API Oficial (AbuseIPDB):** Permite que qualquer usuário insira sua própria chave gratuita na barra lateral para consultar ameaças verificadas com nível de confiança (*Abuse Confidence Score*).
   - 👉 [Criar conta gratuita no AbuseIPDB para gerar sua API Key](https://abuseipdb.com)
3. **Modo Simulação SOC / Aula:** Gera tráfego contínuo de ataques (DDoS, Ransomware, SSH Brute Force, SQL Injection) para demonstrações, estudos e fallback automático.

## 🛠️ Como rodar localmente

```bash
# Clone o repositório
git clone https://github.com
cd void-map

# Instale as dependências
pip install -r requirements.txt

# Execute o painel
streamlit run app.py
```

## 🔒 Segurança

Nenhuma chave de API fica armazenada no código-fonte. Quando utilizada no Modo API Oficial, a chave permanece apenas na memória temporária da sessão do navegador do usuário.
