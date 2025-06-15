import streamlit as st
import tempfile
import pandas as pd
from linux_log_reader import analyze_linux_logs
from mac_floading_reader import analyze_mac_flood_logs
from windows_log_reader import analyze_windows_logs
from iis_log_reader import analyze_iis_logs

st.set_page_config(page_title="Log Analiz Aracı", layout="wide")
st.title("🔍 Log Analiz Platformu")
st.markdown("Log dosyalarını yükleyin, GPT destekli analiz alın.")

def show_results(result):
    if not result:
        st.write("Analiz sonucu yok veya boş.")
        return

    if isinstance(result, list) and all(isinstance(i, dict) for i in result):
        st.subheader("Tablo Görünümü")

     
        table_data = [
            {
                "attack_type": entry.get("attack_type", "Bilinmiyor"),
                "risk_level": entry.get("risk_level", "Bilinmiyor")
            }
            for entry in result
        ]
        df = pd.DataFrame(table_data)
        st.dataframe(df)

        st.subheader("Detaylı Görünüm")
        for i, entry in enumerate(result):
            with st.expander(f"Attack {i+1}: {entry.get('attack_type', 'Bilinmiyor')}"):
                risk = entry.get('risk_level', 'Bilinmiyor')
                color_risk = {
                    "Yüksek": "🔴 **Yüksek**",
                    "Orta": "🟠 **Orta**",
                    "Düşük": "🟢 **Düşük**"
                }.get(risk, f"**{risk}**")
                st.markdown(f"**Risk Seviyesi:** {color_risk}")
                st.markdown(f"**Çözüm Önerisi:** {entry.get('solution', 'Yok')}") 
                st.markdown(f"**Detaylar:**\n\n{entry.get('details', 'Detay yok')}")
    else:
        st.json(result)


tab1, tab2, tab3, tab4 = st.tabs(["🐧 Linux Logları", "🧧 Network Anomaly Logları", "🪟 Windows Güvenlik Logları","🌐 IIS Logları"])


with tab1:
    st.header("Linux Log Analizi")
    uploaded_file = st.file_uploader("Linux log dosyasını yükleyin (.txt)", type=["txt"], key="linux")
    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        result = analyze_linux_logs(tmp_path)
        st.success("✅ Analiz tamamlandı.")
        show_results(result)


with tab2:
    st.header("Network Anomaly Log Analizi")
    uploaded_file = st.file_uploader("Network Anomaly log dosyasını yükleyin (.txt)", type=["txt"], key="mac")
    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        result = analyze_mac_flood_logs(tmp_path)
        st.success("✅ Analiz tamamlandı.")
        show_results(result)

with tab3:
    st.header("Windows Güvenlik Log Analizi")
    uploaded_file = st.file_uploader("Windows güvenlik log dosyasını yükleyin (.txt)", type=["txt"], key="windows")
    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        result = analyze_windows_logs(tmp_path)
        st.success("✅ Analiz tamamlandı.")
        show_results(result)

with tab4:
    st.header("IIS Log Analizi")
    uploaded_file = st.file_uploader("IIS log dosyasını yükleyin (.txt)", type=["txt"], key="iis")
    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        result = analyze_iis_logs(tmp_path)
        st.success("✅ Analiz tamamlandı.")
        show_results(result)
