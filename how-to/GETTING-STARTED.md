# Element Sentinel — Authentication & Authorization System

Dette projekt er en komplet, framework‑agnostisk autentificerings- og autorisationsløsning inspireret af Cartalyst/Sentinel — men fuldstændigt moderniseret og udvidet med:

- Checkpoints (Throttle + Activation)
- Eager-loading styring
- Lokal/standard user‑model politik
- Pluggable repositories
- Remember‑me / persistences
- Throttling med interval + eskaleret backoff
- Lokationsfri konfiguration (YAML/PHP)

Formålet er at levere et **rent, modulært og forudsigeligt API**, som kan bruges på tværs af systemer.

---

# 1. Installation & Opsætning

## 1.1 Installation via Composer

```bash
composer require element/sentinel
