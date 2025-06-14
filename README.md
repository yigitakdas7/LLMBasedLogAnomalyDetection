LLM Tabanlı Log Anomali Tespiti
GPT Destekli Windows Güvenlik Log Analizi Aracı
Siber güvenlik dünyasında sistemler her saniye yüzlerce log üretir. Bu logların manuel olarak analiz edilmesi oldukça zahmetli ve zaman alıcıdır. Peki, bu süreci bir yapay zekâ modeli ile hızlandırmak ve daha verimli hale getirmek mümkün mü?

Bu sorudan yola çıkarak geliştirdiğim bu proje, LLM (Large Language Model) tabanlı bir log analiz aracıdır. Windows sistemlerinden alınan güvenlik loglarını analiz eder, potansiyel tehditleri tespit eder ve GPT destekli açıklamalar sunar.

🚀 Projeyi Nasıl Kullanabilirim?
Projeye başlamak için aşağıdaki adımları takip edebilirsiniz:

Projeyi klonlayın:
git clone https://github.com/yigitakdas7/LLMBasedLogAnomalyDetection.git

cd LLMBasedLogAnomalyDetection

Gerekli Python kütüphanelerini yükleyin:
pip install -r requirements.txt

LLM Apı Key'i alın. Kod dosyaları üzerinden gerekli yerlere ekleyin.

Projeyi başlatın:

streamlit run app.py
Log dosyasını yükleyin:
Açılan arayüzde, .txt formatındaki Windows güvenlik log dosyanızı yükleyin ve analiz başlasın!

🔍 Uygulama Size Neler Sunuyor?
Yapay zekâ modelimiz logları analiz ederek aşağıdaki bilgileri çıkartır:

🚨 Saldırı Türü: GPT, loglar içindeki davranışa göre olası saldırı türünü sınıflandırır.

⚠️ Risk Seviyesi: Tehditin potansiyel tehlikesi (Düşük / Orta / Yüksek) şeklinde derecelendirilir.

📖 Açıklama: Saldırı hakkında GPT tarafından oluşturulan kapsamlı açıklamalar sunulur.

🛡️ Önerilen Önlem: Benzer saldırıların önüne geçmek için alınabilecek güvenlik önlemleri önerilir.
