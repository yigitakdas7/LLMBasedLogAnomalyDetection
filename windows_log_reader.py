# logs/windows_log_reader.py

import requests
import json
import os

API_KEY = "Buraya API KEY giriniz"
BASE_URL = "API KEY"

def read_logs(path):
    try:
        with open(path, "r", encoding="utf-16") as f:
            return f.read()
    except Exception:
        return None

def parse_logs(raw_logs):
    entries = raw_logs.strip().split("TimeCreated")
    parsed = []

    for entry in entries:
        if not entry.strip():
            continue

        log_lines = entry.strip().splitlines()
        log_data = {}
        for line in log_lines:
            if ":" in line:
                key, value = line.split(":", 1)
                log_data[key.strip()] = value.strip()
        if log_data:
            parsed.append({"log": json.dumps(log_data)})
    return parsed

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
            "Aşağıda bir Windows güvenlik log kaydı yer alıyor. "
            "Bu logu şüpheli aktiviteler açısından analiz et. "
            "Sadece geçerli JSON formatında cevap ver:\n"
            "- attack_type (atak tipi)\n"
            "- risk_level (Düşük/Orta/Yüksek)\n"
            "- solution (çözüm önerisi)\n"
            "- details (saldırı açıklaması)\n\n"
            f"Log: {log['log']}\n\n"
            "Lütfen sadece geçerli JSON çıktısı üret."
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
            except Exception:
                break

    return all_results

def analyze_windows_logs(log_file_path):
    raw_logs = read_logs(log_file_path)

    if not raw_logs:
        return {"error": "Log dosyası okunamadı veya boş."}

    parsed_logs = parse_logs(raw_logs)
    result = analyze_logs_with_gpt_separately(parsed_logs)

    return result
