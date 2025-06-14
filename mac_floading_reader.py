

import requests
import json
import os

API_KEY = "Buraya API KEY giriniz"
BASE_URL = "API KEY"

def read_logs(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return None

def parse_logs(raw_logs):
    logs = []
    lines = raw_logs.strip().splitlines()
    for line in lines:
        if line.strip():
            logs.append({"log": line.strip()})
    return logs

def extract_json_objects(text):
    decoder = json.JSONDecoder()
    pos = 0
    results = []

    while pos < len(text):
        try:
            obj, idx = decoder.raw_decode(text[pos:])
            results.append(obj)
            pos += idx
        except json.JSONDecodeError:
            pos += 1

    return results

def analyze_logs_with_gpt_separately(logs, max_retries=3):
    all_results = []

    for i, log in enumerate(logs[:6]):
        prompt = (
            "Aşağıda ağ sisteminden alınan bir log kaydı var. "
            "Bu logu MAC Flooding veya benzeri Layer 2 saldırılar açısından analiz et ve JSON olarak şu bilgileri ver:\n"
            "- attack_type (atak tipi)\n"
            "- risk_level (Düşük/Orta/Yüksek)\n"
            "- solution (çözüm önerisi)\n"
            "- details (saldırı açıklaması)\n\n"
            f"Log: {log['log']}\n\n"
            "Lütfen yalnızca geçerli JSON çıktısı ver."
        )

        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        }

        data = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt},
            ],
        }

        for attempt in range(max_retries):
            try:
                response = requests.post(BASE_URL, headers=headers, json=data)
                if response.status_code == 200:
                    raw_result = response.json()["choices"][0]["message"]["content"]
                    result_json = extract_json_objects(raw_result)
                    if result_json:
                        all_results.extend(result_json)
                        break
                else:
                    break
            except Exception:
                break

    return all_results

def analyze_mac_flood_logs(log_file_path):
    raw_logs = read_logs(log_file_path)

    if not raw_logs:
        return {"error": "Log dosyası okunamadı veya boş."}

    parsed_logs = parse_logs(raw_logs)
    result = analyze_logs_with_gpt_separately(parsed_logs)

    return result
