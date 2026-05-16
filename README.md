# Password Tool

[🇧🇷 Português](#português) | [🇺🇸 English](#english)

<a name="português"></a>
# 🇧🇷 Português

Analisador e gerador de senhas seguras em Python puro — sem dependências externas.

Projeto educacional de cibersegurança que demonstra conceitos de **entropia**, **força bruta** e **geração criptograficamente segura** de senhas.

## Funcionalidades

- **Análise de senha**: score de força (0–6), entropia em bits, tempo estimado para quebrar por força bruta, critérios detalhados e sugestões de melhoria
- **Gerador de senha**: usa `secrets.SystemRandom` (CSPRNG) com garantia de presença de cada tipo de caractere habilitado — letras, números e símbolos especiais
- **Verificador de vazamentos**: integração com a API [Have I Been Pwned](https://haveibeenpwned.com) via k-Anonymity — a senha nunca trafega pela rede
- **Detector de dicionário**: detecta palavras comuns, padrões de teclado, leet-speak e sequências repetidas localmente, sem rede
- **Scan de variantes**: gera e verifica até 50 variações de uma palavra-base na HIBP (casing, leet, sufixos numéricos/símbolos), com índice de risco de ataque de dicionário (0–4)
- **CLI completa** com saída colorida no terminal

## Instalação

```bash
git clone https://github.com/seu-usuario/password-tool.git
cd password-tool

# Sem dependências externas — Python 3.10+ é suficiente
# Para rodar os testes:
pip install pytest
```

## Uso via CLI

### Analisar uma senha

```bash
python CLI.py analyze "minhasenha123"
python CLI.py analyze "xK#9mPqL!2vRn\$Wd"

# Análise offline (sem consultar a HIBP)
python CLI.py analyze "minhasenha123" --no-scan
```

### Gerar uma senha

```bash
# Padrão: 20 caracteres, todos os tipos
python CLI.py generate

# 32 caracteres, sem símbolos
python CLI.py generate --length 32 --no-symbols

# Gerar e já analisar
python CLI.py generate --length 24 --analyze
```

### Verificar vazamentos (senha exata)

```bash
python CLI.py pwned "minhasenha123"
```

A saída exibe o hash SHA-1, o prefixo enviado à API e o sufixo verificado localmente — para ilustrar como o k-Anonymity funciona na prática.

### Escanear variantes de uma palavra

```bash
# Até 50 variantes (padrão)
python CLI.py word alface

# Limitar a 20 variantes
python CLI.py word alface --limit 20

# Exibir também variantes não comprometidas
python CLI.py word alface --show-safe
```

## Uso como biblioteca

```python
from Analyzer import analyze
from Generator import GeneratorConfig, generate
from Pwned import check_pwned
from DictionaryChecker import check_dictionary
from WordVariants import scan_word

# Analisar (inclui check de dicionário e scan de variantes HIBP)
result = analyze("Tr0ub4dor&3")
print(result.strength_label)          # "strong"
print(result.entropy_bits)            # ex: 72.54
print(result.crack_time_human)        # ex: "billions of years"
print(result.dictionary_risk_label)   # "none" / "low" / "moderate" / "high" / "critical"
print(result.suggestions)             # lista de melhorias

# Analisar sem consultar a HIBP
result = analyze("minhasenha123", skip_variant_scan=True)

# Gerar
config = GeneratorConfig(length=24, symbols=True)
senha = generate(config)
print(senha)                           # ex: "xK#9mPqL!2vRn$WdQe@7Bc"

# Verificar vazamentos (senha exata)
result = check_pwned("minhasenha123")
print(result.found)                    # True ou False
print(result.count)                    # número de vazamentos
print(result.message)                  # mensagem formatada

# Verificar dicionário localmente
result = check_dictionary("p@ssw0rd")
print(result.is_weak)                  # True
print(result.warnings)                 # lista de avisos

# Escanear variantes de uma palavra
scan = scan_word("alface")
print(scan.found_count)                # variantes comprometidas
print(scan.total_breach_appearances)   # total de aparições
```

## Como os cálculos funcionam

### Entropia

A entropia mede a imprevisibilidade de uma senha em bits:

```
entropia = tamanho × log₂(pool)
```

Onde `pool` é o número de caracteres possíveis:

| Tipos usados | Pool |
|---|---|
| Só minúsculas | 26 |
| + Maiúsculas | 52 |
| + Números | 62 |
| + Símbolos | 94 |

Cada bit adicional **dobra** o número de combinações possíveis.

### Tempo de quebra estimado

Assume um ataque de força bruta com **10 milhões de tentativas/segundo** (hardware moderno com GPU, hash MD5):

```
tempo = (2^entropia / 2) / 10_000_000
```

> Essa estimativa é conservadora para hashes rápidos (MD5, SHA-1). Algoritmos lentos como bcrypt/Argon2 aumentam o tempo por fatores de 10.000x ou mais.

### Índice de risco de dicionário

Mede a exposição a ataques de dicionário direcionados com base em quantas variantes da palavra-base foram encontradas na HIBP. É **independente da entropia** — uma senha pode ter entropia alta e risco de dicionário crítico ao mesmo tempo.

| Variantes comprometidas | Nível | Label |
|---|---|---|
| 0 | 0 | none |
| 1–3 | 1 | low |
| 4–10 | 2 | moderate |
| 11–30 | 3 | high |
| 31+ | 4 | critical |

### Por que `secrets` e não `random`?

`random` usa um gerador pseudoaleatório (Mersenne Twister) **previsível** — dado o estado interno, é possível prever os próximos valores. O módulo `secrets` usa a fonte de entropia do sistema operacional (`/dev/urandom` no Linux), adequada para fins criptográficos.

## Testes

```bash
python -m pytest tests/ -v
```

Cobertura dos testes:
- Cálculo de entropia e charset
- Todos os critérios de análise
- Formato do tempo de quebra
- Comprimento e composição das senhas geradas
- Validações de configuração
- Unicidade das senhas geradas
- Hashing SHA-1 e divisão do hash (pwned)
- Parsing da resposta da API HIBP (pwned)
- Comportamento com mock da API (pwned)
- Normalização leet-speak e detecção de padrões (DictionaryChecker)
- Geração de variantes e deduplicação (WordVariants)

Para rodar apenas os testes de integração com a API real:

```bash
python -m pytest tests/test_pwned.py -v -m integration
```

## Estrutura do projeto

```
password-tool/
├── Analyzer.py              # Lógica de análise, entropia e índice de risco
├── Generator.py             # Geração segura com secrets
├── CLI.py                   # Interface de linha de comando
├── Pwned.py                 # Verificador de vazamentos (HIBP k-Anonymity)
├── DictionaryChecker.py     # Detecção local de palavras, padrões e leet-speak
├── WordVariants.py          # Geração de variantes e scan em lote na HIBP
├── tests/
│   ├── test_password_tool.py
│   └── test_pwned.py
└── README.md
```

## Conceitos de segurança demonstrados

- **Entropia da informação** (Shannon)
- **Ataques de força bruta** e estimativa de tempo
- **Ataques de dicionário** e mutações baseadas em regras
- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator)
- **Pool de caracteres** e sua influência na segurança
- **k-Anonymity** aplicado à verificação de senhas sem expor dados à API
- **Normalização leet-speak** para detecção de variantes ofuscadas

## Próximos passos sugeridos

- [x] Detectar senhas baseadas em palavras do dicionário (ataque de dicionário)
- [x] Verificar se a senha aparece em vazamentos via [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [x] Detectar padrões fracos (sequências como `1234`, `aaaa`, `qwerty`)
- [x] Escanear variantes de uma palavra-base na HIBP com índice de risco
- [ ] Exportar relatório em JSON

## Referências

- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Python `secrets` module](https://docs.python.org/3/library/secrets.html)
- [Have I Been Pwned](https://haveibeenpwned.com)

[Voltar ao topo](#-password-tool)

---

<a name="english"></a>
# 🇺🇸 English

A secure password analyzer and generator in pure Python — no external dependencies required.

An educational cybersecurity project demonstrating concepts of **entropy**, **brute-force attacks**, and **cryptographically secure password generation**.

## Features

- **Password analysis**: strength score (0–6), entropy in bits, estimated brute-force crack time, detailed criteria checks, and improvement suggestions
- **Password generator**: uses `secrets.SystemRandom` (CSPRNG) with guaranteed presence of each enabled character type — letters, digits, and special symbols
- **Breach checker**: integrates with the [Have I Been Pwned](https://haveibeenpwned.com) API via k-Anonymity — the password never travels over the network
- **Dictionary detector**: locally detects common words, keyboard patterns, leet-speak, and repeated sequences — no network required
- **Variant scanner**: generates and checks up to 50 variations of a base word against HIBP (casing, leet, numeric/symbol suffixes), with a dictionary attack risk index (0–4)
- **Full CLI** with colored terminal output

## Installation

```bash
git clone https://github.com/your-username/password-tool.git
cd password-tool

# No external dependencies — Python 3.10+ is enough
# To run the tests:
pip install pytest
```

## CLI Usage

### Analyze a password

```bash
python CLI.py analyze "mypassword123"
python CLI.py analyze "xK#9mPqL!2vRn\$Wd"

# Offline analysis (skip HIBP variant scan)
python CLI.py analyze "mypassword123" --no-scan
```

### Generate a password

```bash
# Default: 20 characters, all types enabled
python CLI.py generate

# 32 characters, no symbols
python CLI.py generate --length 32 --no-symbols

# Generate and immediately analyze
python CLI.py generate --length 24 --analyze
```

### Check for breaches (exact password)

```bash
python CLI.py pwned "mypassword123"
```

The output displays the SHA-1 hash, the prefix sent to the API, and the suffix checked locally — illustrating how k-Anonymity works in practice.

### Scan variants of a word

```bash
# Up to 50 variants (default)
python CLI.py word alface

# Limit to 20 variants
python CLI.py word alface --limit 20

# Also show variants not found in any breach
python CLI.py word alface --show-safe
```

## Usage as a library

```python
from Analyzer import analyze
from Generator import GeneratorConfig, generate
from Pwned import check_pwned
from DictionaryChecker import check_dictionary
from WordVariants import scan_word

# Analyze (includes dictionary check and HIBP variant scan)
result = analyze("Tr0ub4dor&3")
print(result.strength_label)          # "strong"
print(result.entropy_bits)            # e.g. 72.54
print(result.crack_time_human)        # e.g. "billions of years"
print(result.dictionary_risk_label)   # "none" / "low" / "moderate" / "high" / "critical"
print(result.suggestions)             # list of improvement tips

# Analyze without HIBP network call
result = analyze("mypassword123", skip_variant_scan=True)

# Generate
config = GeneratorConfig(length=24, symbols=True)
password = generate(config)
print(password)                        # e.g. "xK#9mPqL!2vRn$WdQe@7Bc"

# Check for breaches (exact password)
result = check_pwned("mypassword123")
print(result.found)                    # True or False
print(result.count)                    # number of times seen in breaches
print(result.message)                  # formatted result message

# Check dictionary locally
result = check_dictionary("p@ssw0rd")
print(result.is_weak)                  # True
print(result.warnings)                 # list of warnings

# Scan variants of a word
scan = scan_word("alface")
print(scan.found_count)                # compromised variants
print(scan.total_breach_appearances)   # total breach appearances
```

## How the calculations work

### Entropy

Entropy measures the unpredictability of a password in bits:

```
entropy = length × log₂(pool)
```

Where `pool` is the number of possible characters:

| Character types used | Pool size |
|---|---|
| Lowercase only | 26 |
| + Uppercase | 52 |
| + Digits | 62 |
| + Symbols | 94 |

Each additional bit **doubles** the number of possible combinations.

### Estimated crack time

Assumes a brute-force attack at **10 million guesses/second** (modern GPU, MD5 hash):

```
time = (2^entropy / 2) / 10_000_000
```

> This estimate is conservative for fast hashes (MD5, SHA-1). Slow algorithms like bcrypt/Argon2 increase the time by factors of 10,000x or more.

### Dictionary attack risk index

Measures exposure to targeted dictionary attacks based on how many variants of the password's base word were found in HIBP. It is **independent of entropy** — a password can have high entropy and a critical dictionary risk at the same time.

| Compromised variants | Level | Label |
|---|---|---|
| 0 | 0 | none |
| 1–3 | 1 | low |
| 4–10 | 2 | moderate |
| 11–30 | 3 | high |
| 31+ | 4 | critical |

### Why `secrets` instead of `random`?

`random` uses a pseudorandom generator (Mersenne Twister) that is **predictable** — given its internal state, future values can be derived. The `secrets` module draws from the operating system's entropy source (`/dev/urandom` on Linux), making it suitable for cryptographic use.

## Tests

```bash
python -m pytest tests/ -v
```

Test coverage includes:
- Entropy and charset size calculation
- All analysis criteria checks
- Crack time formatting
- Generated password length and composition
- Configuration validation
- Password uniqueness
- SHA-1 hashing and hash splitting (pwned)
- HIBP API response parsing (pwned)
- Mock-based API behavior tests (pwned)
- Leet-speak normalization and pattern detection (DictionaryChecker)
- Variant generation and deduplication (WordVariants)

To run only the live integration tests against the real API:

```bash
python -m pytest tests/test_pwned.py -v -m integration
```

## Project structure

```
password-tool/
├── Analyzer.py              # Analysis logic: entropy, scoring, risk index
├── Generator.py             # Secure generation using secrets
├── CLI.py                   # Command-line interface
├── Pwned.py                 # Breach checker (HIBP k-Anonymity)
├── DictionaryChecker.py     # Local detection of words, patterns, and leet-speak
├── WordVariants.py          # Variant generation and batch HIBP scan
├── tests/
│   ├── test_password_tool.py
│   └── test_pwned.py
└── README.md
```

## Security concepts demonstrated

- **Information entropy** (Shannon)
- **Brute-force attacks** and time estimation
- **Dictionary attacks** and rule-based mutations
- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator)
- **Character pool size** and its impact on security
- **k-Anonymity** applied to password breach checking without exposing data to the API
- **Leet-speak normalization** for detecting obfuscated variants

## Suggested next steps

- [x] Detect passwords based on dictionary words (dictionary attack simulation)
- [x] Check if a password has appeared in known data breaches via the [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [x] Flag forbidden patterns (e.g. sequences like `1234`, `aaaa`, `qwerty`)
- [x] Scan base word variants against HIBP with a dictionary risk index
- [ ] Export analysis report as JSON

## References

- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Python `secrets` module](https://docs.python.org/3/library/secrets.html)
- [Have I Been Pwned](https://haveibeenpwned.com)

[Back to top](#-password-tool)
