## Session Cookie Analyzer

**Description**  
A comprehensive security tool that analyzes session cookies for common vulnerabilities and misconfigurations. It automatically flags missing security flags and provides actionable recommendations.

**Key Security Checks**
- Missing `Secure` flag (cookies sent over HTTP)
- Missing `HttpOnly` flag (XSS vulnerability)
- Weak or missing `SameSite` attribute (CSRF risk)
- Overly long cookie expiration times
- Suspicious cookie naming patterns

**Risk Levels**
- **High** — Critical issues (Secure/HttpOnly missing)
- **Medium** — Moderate concerns (SameSite, expiration)
- **Low** — Good configuration

**CSV Format Example**
```csv
cookie_name,domain,path,secure,httponly,samesite,expires
session_id,example.com,/,true,true,Lax,2026-12-31 23:59:59
auth_token,example.com,/,false,false,None,2026-04-10 10:00:00
```

## Custom Wordlist Generator (OSINT əsaslı)

**Təsvir**  
OSINT vasitəsilə toplanmış şəxsi məlumatlara əsasən hədəf yönümlü parol wordlist-i yaradan interaktiv alət.  
Real həyatda insanlar ad, soyad, doğum tarixi, ev heyvanı, şirkət və s. məlumatlardan parol düzəldirlər. Bu tool məhz bu cür kombinasiyaları avtomatik yaradır.

**Xüsusiyyətlər**
- Ad, soyad, ləqəb, doğum tarixi, partnyor, ev heyvanı, şirkət və sevimli rəqəm daxil etmək
- Leetspeak (a→@, e→3 və s.), simvol əlavəsi, tarix kombinasiyaları
- GUI interfeys (asanlıqla istifadə)
- Wordlist-i `.txt` fayl kimi saxlama imkanı
- Azərbaycan dilini dəstəkləyir

**Necə işlətmək**
```bash
python3 custom_wordlist_generator.py
