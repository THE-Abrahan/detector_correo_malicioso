import re
import sys
import json
import tldextract
from urllib.parse import urlparse

MAX_SCORE = 10

# Lista blanca de dominios legítimos
WHITELIST_DOMAINS = ["microsoft.com", "google.com", "paypal.com", "apple.com", "outlook.com", 
                     "amazon.com", "facebook.com", "twitter.com", "linkedin.com", "github.com",
                     "banco.com", "santander.com", "bbva.com", "caixabank.com", "bankia.com"]

# Palabras clave sospechosas
SUSPICIOUS_KEYWORDS = ["urgente", "inmediatamente", "verificar", "bloqueado", "cuenta suspendida", "premio"]
PHISHING_PATTERNS = ["inicie sesión", "confirme su cuenta", "actualice su información"]

def calculate_score(raw_score):
    return min(raw_score, MAX_SCORE)

def analyze_headers(header_text):
    score = 0
    indicators = []
    
    # Verificar encabezados importantes
    headers_to_check = ["From", "To", "Subject", "Date", "Return-Path"]
    found_headers = []
    
    for header in headers_to_check:
        if re.search(rf"^{header}:", header_text, re.MULTILINE | re.IGNORECASE):
            found_headers.append(header)
        else:
            indicators.append(f"Falta encabezado: {header}")
            score += 1
    
    # Verificar autenticación SPF, DKIM, DMARC
    if "Received-SPF" not in header_text:
        indicators.append("Falta verificación SPF")
        score += 1
        
    if "Authentication-Results" not in header_text:
        indicators.append("Falta verificación de autenticación")
        score += 1
    
    return score, indicators

def analyze_sender(header_text):
    result = {}
    score = 0
    indicators = []

    match = re.search(r"From:\s*.*<(.+?)>|From:\s*(.+)", header_text, re.IGNORECASE)
    if match:
        email = match.group(1) or match.group(2)
        result["email"] = email.strip()
        domain = email.split("@")[-1].lower()
        result["domain"] = domain

        # Si no está en whitelist, analizar
        if domain not in WHITELIST_DOMAINS:
            # Buscar typosquatting: microsoft vs microsft
            if re.search(r"(micosoft|microsft|micros0ft|paypa1|g00gle|amaz0n)", domain):
                indicators.append(f"Dominio sospechoso: {domain}")
                score += 3
            if not re.search(r"\.", domain):
                indicators.append("Dominio sin punto, inusual")
                score += 2
        else:
            indicators.append(f"Dominio seguro detectado: {domain}")

    return result, score, indicators

def analyze_links(text):
    result = []
    score = 0
    indicators = []

    urls = re.findall(r"https?://[^\s<>]+|www\.[^\s<>]+", text)
    for url in urls:
        if not url.startswith('http'):
            url = 'http://' + url
            
        url_info = {"url": url, "suspicious": False, "reasons": []}
        parsed = urlparse(url)
        domain_info = tldextract.extract(parsed.netloc)
        domain = f"{domain_info.domain}.{domain_info.suffix}"

        if domain not in WHITELIST_DOMAINS:
            if re.search(r"(bit\.ly|tinyurl\.com|goo\.gl|t\.co|bitly\.com|ow\.ly)", url):
                url_info["suspicious"] = True
                url_info["reasons"].append("Enlace acortado")
                indicators.append(f"Enlace acortado detectado: {url}")
                score += 2

            if re.match(r"^https?://\d+\.\d+\.\d+\.\d+", url):
                url_info["suspicious"] = True
                url_info["reasons"].append("Dirección IP en URL")
                indicators.append(f"Enlace con IP detectado: {url}")
                score += 3

            if "@" in parsed.netloc:
                url_info["suspicious"] = True
                url_info["reasons"].append("URL con @ sospechosa")
                indicators.append(f"URL sospechosa: {url}")
                score += 2

        result.append(url_info)

    return result, score, indicators

def analyze_content(text):
    score = 0
    indicators = []
    
    # Palabras clave de urgencia
    urgency_keywords = ["urgente", "inmediatamente", "ahora", "última oportunidad", "24 horas", "48 horas"]
    for keyword in urgency_keywords:
        if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
            indicators.append(f"Lenguaje de urgencia: '{keyword}'")
            score += 1
    
    # Solicitudes de información personal
    personal_info_keywords = ["contraseña", "número de tarjeta", "CVV", "SSN", "credenciales", "iniciar sesión"]
    for keyword in personal_info_keywords:
        if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
            indicators.append(f"Solicitud de información sensible: '{keyword}'")
            score += 2
    
    # Amenazas
    threat_keywords = ["cuenta suspendida", "bloqueado", "cerrar", "eliminar", "problema de seguridad"]
    for keyword in threat_keywords:
        if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
            indicators.append(f"Amenaza detectada: '{keyword}'")
            score += 2
    
    # Premios o ofertas
    offer_keywords = ["premio", "ganador", "gratis", "oferta", "descuento", "regalo"]
    for keyword in offer_keywords:
        if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
            indicators.append(f"Oferta sospechosa: '{keyword}'")
            score += 1
    
    return score, indicators

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Modo de prueba con contenido predefinido
        test_email = "From: security@micr0soft.com\nTo: usuario@example.com\nSubject: Urgent account verification needed\n\nPlease verify your account immediately at http://bit.ly/fake-link"
        email_text = test_email
    else:
        # Leer de stdin
        email_text = sys.stdin.read()
    
    # Separar encabezados y cuerpo
    header_end = email_text.find("\n\n")
    if header_end == -1:
        header_text = email_text
        body_text = ""
    else:
        header_text = email_text[:header_end]
        body_text = email_text[header_end + 2:]
    
    total_score = 0
    all_indicators = []
    
    # Análisis de encabezados
    header_score, header_indicators = analyze_headers(header_text)
    total_score += header_score
    all_indicators.extend(header_indicators)
    
    # Análisis del remitente
    sender_analysis, s_score, s_indicators = analyze_sender(header_text)
    total_score += s_score
    all_indicators.extend(s_indicators)
    
    # Análisis de enlaces (tanto en encabezados como en cuerpo)
    link_analysis, l_score, l_indicators = analyze_links(header_text + " " + body_text)
    total_score += l_score
    all_indicators.extend(l_indicators)
    
    # Análisis de contenido
    content_score, content_indicators = analyze_content(body_text)
    total_score += content_score
    all_indicators.extend(content_indicators)
    
    # Calcular puntuación final
    final_score = min(total_score, MAX_SCORE)
    risk_percent = (final_score / MAX_SCORE) * 100
    
    # Determinar estado
    if final_score >= 7:
        status = "Malicioso"
    elif final_score >= 4:
        status = "Sospechoso"
    else:
        status = "Seguro"
    
    # Preparar resultado
    result = {
        "score": final_score,
        "risk_percent": round(risk_percent, 1),
        "status": status,
        "indicators": all_indicators,
        "details": {
            "sender_analysis": sender_analysis,
            "link_analysis": link_analysis,
            "content_score": content_score
        }
    }
    
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()