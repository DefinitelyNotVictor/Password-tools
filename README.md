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

### Verificar vazamentos

```bash
python CLI.py pwned "minhasenha123"
```

A saída mostra o resultado e exibe o hash SHA-1, o prefixo enviado à API e o sufixo verificado localmente — para ilustrar como o k-Anonymity funciona na prática.

## Uso como biblioteca

```python
from Analyzer import analyze
from Generator import GeneratorConfig, generate
from pwned import check_pwned

# Analisar
result = analyze("Tr0ub4dor&3")
print(result.strength_label)      # "forte"
print(result.entropy_bits)        # ex: 72.54
print(result.crack_time_human)    # ex: "milhões de anos"
print(result.suggestions)         # lista de melhorias

# Gerar
config = GeneratorConfig(length=24, symbols=True)
senha = generate(config)
print(senha)                       # ex: "xK#9mPqL!2vRn$WdQe@7Bc"

# Verificar vazamentos
result = check_pwned("minhasenha123")
print(result.found)               # True ou False
print(result.count)               # número de vazamentos
print(result.message)             # mensagem formatada
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

Para rodar apenas os testes de integração com a API real:

```bash
python -m pytest tests/test_pwned.py -v -m integration
```

## Estrutura do projeto

```
password-tool/
├── Analyzer.py              # Lógica de análise e entropia
├── Generator.py             # Geração segura com secrets
├── CLI.py                   # Interface de linha de comando
├── pwned.py                 # Verificador de vazamentos (HIBP k-Anonymity)
├── tests/
│   ├── test_password_tool.py
│   └── test_pwned.py
└── README.md
```

## Conceitos de segurança demonstrados

- **Entropia da informação** (Shannon)
- **Ataques de força bruta** e estimativa de tempo
- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator)
- **Pool de caracteres** e sua influência na segurança
- **k-Anonymity** aplicado à verificação de senhas sem expor dados à API

## Próximos passos sugeridos

- [ ] Detectar senhas baseadas em palavras do dicionário (ataque de dicionário)
- [x] Verificar se a senha aparece em vazamentos via [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [ ] Adicionar suporte a senhas com padrões proibidos (ex: sequências como `1234`)
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

### Check for breaches

```bash
python CLI.py pwned "mypassword123"
```

The output shows the result and displays the SHA-1 hash, the prefix sent to the API, and the suffix checked locally — illustrating how k-Anonymity works in practice.

## Usage as a library

```python
from Analyzer import analyze
from Generator import GeneratorConfig, generate
from pwned import check_pwned

# Analyze
result = analyze("Tr0ub4dor&3")
print(result.strength_label)      # "strong"
print(result.entropy_bits)        # e.g. 72.54
print(result.crack_time_human)    # e.g. "millions of years"
print(result.suggestions)         # list of improvement tips

# Generate
config = GeneratorConfig(length=24, symbols=True)
password = generate(config)
print(password)                   # e.g. "xK#9mPqL!2vRn$WdQe@7Bc"

# Check for breaches
result = check_pwned("mypassword123")
print(result.found)               # True or False
print(result.count)               # number of times seen in breaches
print(result.message)             # formatted result message
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

To run only the live integration tests against the real API:

```bash
python -m pytest tests/test_pwned.py -v -m integration
```

## Project structure

```
password-tool/
├── Analyzer.py              # Analysis logic: entropy, scoring, crack time
├── Generator.py             # Secure generation using secrets
├── CLI.py                   # Command-line interface
├── pwned.py                 # Breach checker (HIBP k-Anonymity)
├── tests/
│   ├── test_password_tool.py
│   └── test_pwned.py
└── README.md
```

## Security concepts demonstrated

- **Information entropy** (Shannon)
- **Brute-force attacks** and time estimation
- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator)
- **Character pool size** and its impact on security
- **k-Anonymity** applied to password breach checking without exposing data to the API

## Suggested next steps

- [ ] Detect passwords based on dictionary words (dictionary attack simulation)
- [x] Check if a password has appeared in known data breaches via the [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [ ] Flag forbidden patterns (e.g. sequences like `1234`, `aaaa`)
- [ ] Export analysis report as JSON

## References

- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Python `secrets` module](https://docs.python.org/3/library/secrets.html)
- [Have I Been Pwned](https://haveibeenpwned.com)

[Back to top](#-password-tool)
