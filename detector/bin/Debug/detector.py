import re
import json
import sys
from urllib.parse import urlparse
import tldextract

class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            "urgente", "verifique", "actualice", "contraseña", "clic aquí", 
            "ganador", "premio", "gratis", "cuenta suspendida", "seguridad",
            "confirmar", "restablecer", "banco", "paypal", "netflix", "amazon",
            "ofertA", "exclusivO", "limitadO", "acción requerida", "problema de cuenta",
            "factura", "desbloquear", "inicio de sesión", "verificación", "alertA"
        ]
        
        self.shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
                                 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'shorte.st']
        
        self.legitimate_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
                                  'netflix.com', 'paypal.com', 'facebook.com', 'twitter.com',
                                  'instagram.com', 'linkedin.com', 'github.com', 'ebay.com']

    def analyze_email(self, email_content):
        results = {
            "score": 0,
            "status": "Seguro",
            "indicators": [],
            "details": {
                "sender_analysis": {},
                "link_analysis": [],
                "content_analysis": {}
            }
        }
        
        # Análisis del remitente
        sender_indicators = self.analyze_sender(email_content)
        results["score"] += sender_indicators["score"]
        results["indicators"].extend(sender_indicators["indicators"])
        results["details"]["sender_analysis"] = sender_indicators["details"]
        
        # Análisis de enlaces
        link_indicators = self.analyze_links(email_content)
        results["score"] += link_indicators["score"]
        results["indicators"].extend(link_indicators["indicators"])
        results["details"]["link_analysis"] = link_indicators["details"]
        
        # Análisis de contenido
        content_indicators = self.analyze_content(email_content)
        results["score"] += content_indicators["score"]
        results["indicators"].extend(content_indicators["indicators"])
        results["details"]["content_analysis"] = content_indicators["details"]
        
        # Limitar la puntuación máxima a 10
        results["score"] = min(results["score"], 10)
        
        # Determinar estado final
        if results["score"] >= 8:
            results["status"] = "Malicioso"
        elif results["score"] >= 4:
            results["status"] = "Sospechoso"
        else:
            results["status"] = "Seguro"
        
        return results

    def analyze_sender(self, email_content):
        score = 0
        indicators = []
        details = {}
        
        # Expresión regular para encontrar el remitente
        sender_match = re.search(r'From:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_content, re.IGNORECASE)
        
        if sender_match:
            sender_email = sender_match.group(1)
            details["email"] = sender_email
            
            # Extraer dominio
            domain = sender_email.split('@')[1]
            details["domain"] = domain
            
            # Verificar dominio sospechoso
            if self.is_suspicious_domain(domain):
                score += 3
                indicators.append(f"Dominio de remitente sospechoso: {domain}")
        
        return {"score": score, "indicators": indicators, "details": details}

    def analyze_links(self, email_content):
        score = 0
        indicators = []
        details = []
        
        try:
            # Encontrar todos los enlaces
            links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
            
            for link in links:
                try:
                    link_details = {"url": link, "suspicious": False, "reasons": []}
                    
                    if not link.startswith(('http://', 'https://')):
                        link = 'http://' + link
                    
                    # Verificar si es un enlace acortado
                    if self.is_shortened_url(link):
                        score += 2
                        indicators.append(f"Enlace acortado detectado: {link}")
                        link_details["suspicious"] = True
                        link_details["reasons"].append("Enlace acortado")
                    
                    # Verificar si el dominio es sospechoso
                    domain = self.extract_domain(link)
                    if self.is_suspicious_domain(domain):
                        score += 3
                        indicators.append(f"Dominio sospechoso en enlace: {domain}")
                        link_details["suspicious"] = True
                        link_details["reasons"].append("Dominio sospechoso")
                    
                    # Verificar si usa IP en lugar de dominio
                    if self.contains_ip_address(link):
                        score += 3
                        indicators.append(f"Enlace con dirección IP: {link}")
                        link_details["suspicious"] = True
                        link_details["reasons"].append("Usa dirección IP")
                    
                    details.append(link_details)
                except Exception as e:
                    # Registrar error pero continuar con otros enlaces
                    print(f"Error analizando enlace {link}: {str(e)}", file=sys.stderr)
                    continue
                    
        except Exception as e:
            print(f"Error en el análisis de enlaces: {str(e)}", file=sys.stderr)
        
        return {"score": score, "indicators": indicators, "details": details}

    def analyze_content(self, email_content):
        score = 0
        indicators = []
        details = {"keyword_matches": []}
        content_lower = email_content.lower()
        
        # Verificar palabras clave sospechosas
        for keyword in self.suspicious_keywords:
            if re.search(r'\b' + re.escape(keyword) + r'\b', content_lower):
                score += 1
                indicators.append(f"Palabra clave sospechosa: '{keyword}'")
                details["keyword_matches"].append(keyword)
        
        # Detectar lenguaje urgente o amenazante
        urgency_patterns = [
            r"24 horas", r"48 horas", r"inmediatamente", r"ahora mismo", 
            r"cuenta suspendida", r"acción inmediata", r"última oportunidad"
        ]
        
        for pattern in urgency_patterns:
            if re.search(pattern, content_lower):
                score += 2
                indicators.append("Lenguaje urgente o amenazante detectado")
                details["urgency_detected"] = True
                break
        
        # Detectar solicitud de información personal
        personal_info_patterns = [
            r"contraseña", r"credenciales", r"tarjeta de crédito", 
            r"número de seguro", r"información personal", r"datos bancarios"
        ]
        
        for pattern in personal_info_patterns:
            if re.search(pattern, content_lower):
                score += 3
                indicators.append("Solicitud de información personal detectada")
                details["personal_info_request"] = True
                break
        
        return {"score": score, "indicators": indicators, "details": details}

    def is_shortened_url(self, url):
        domain = self.extract_domain(url)
        return domain in self.shortener_domains

    def extract_domain(self, url):
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"

    def is_suspicious_domain(self, domain):
        # Verificar si el dominio es similar a uno legítimo (typosquatting)
        for legit_domain in self.legitimate_domains:
            if self.is_similar_domain(domain, legit_domain):
                return True
        
        # Verificar si es un dominio nuevo o poco común
        if domain.count('.') > 1 or len(domain) > 30:
            return True
            
        return False

    def is_similar_domain(self, domain, legit_domain):
        # Detectar typosquatting calculando similitud
        if domain == legit_domain:
            return False
            
        # Verificar diferencias mínimas (typosquatting)
        if len(domain) == len(legit_domain):
            diff_count = sum(1 for a, b in zip(domain, legit_domain) if a != b)
            if diff_count <= 2:
                return True
        
        # Verificar adición/eliminación de caracteres
        if domain in legit_domain or legit_domain in domain:
            if abs(len(domain) - len(legit_domain)) <= 2:
                return True
                
        return False

    def contains_ip_address(self, text):
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        return re.search(ip_pattern, text) is not None

if __name__ == "__main__":
    # Leer el contenido del correo desde la entrada estándar
    email_content = sys.stdin.read()
    
    # Analizar el correo
    detector = PhishingDetector()
    results = detector.analyze_email(email_content)
    
    # Imprimir resultados como JSON
    print(json.dumps(results, ensure_ascii=False))