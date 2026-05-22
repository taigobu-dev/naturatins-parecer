# NATURATINS — Parecer Técnico · Sistema Multi-Usuário

Sistema seguro de geração de pareceres com autenticação JWT,
banco PostgreSQL e proteção contra ataques.

---

## Estrutura de arquivos

```
naturatins-parecer/
├── app.py              ← API Flask com autenticação e banco de dados
├── index.html          ← Frontend com login, painel admin e formulário
├── requirements.txt    ← Dependências Python
├── render.yaml         ← Deploy completo no Render (API + PostgreSQL)
└── README.md
```

---

## Segurança implementada

| Proteção                        | Como foi implementado                          |
|---------------------------------|------------------------------------------------|
| Autenticação JWT                | Token com expiração de 8h, assinado com HS256  |
| Senhas com hash                 | bcrypt com 12 rounds de salt                   |
| Rate limiting                   | Máx. 10 tentativas de login por minuto por IP  |
| Bloqueio de conta               | 5 falhas → bloqueio automático de 30 min       |
| CORS restrito                   | Apenas origens autorizadas na variável de env  |
| Headers de segurança HTTP       | X-Frame-Options, X-XSS-Protection, HSTS etc.  |
| Validação de força de senha     | Mín. 10 chars, maiúsc., minúsc., número e especial |
| Log de auditoria                | Toda ação registrada com IP, usuário e horário |
| Variáveis de ambiente           | Credenciais nunca no código                    |
| Resposta genérica no login      | Não revela se e-mail existe ou não             |

---

## Deploy no Render.com

### 1. Suba para o GitHub

```bash
git init
git add .
git commit -m "sistema naturatins"
git remote add origin https://github.com/SEU-USUARIO/naturatins-parecer.git
git push -u origin main
```

### 2. Crie o serviço no Render

1. Acesse [render.com](https://render.com) → **New → Web Service**
2. Conecte o repositório GitHub
3. O Render detecta o `render.yaml` automaticamente
4. Clique em **Deploy**

### 3. Configure as variáveis de ambiente

No painel do Render → **Settings → Environment**:

| Variável              | Como gerar / valor                                        |
|-----------------------|-----------------------------------------------------------|
| `JWT_SECRET`          | `python -c "import secrets; print(secrets.token_hex(64))"` |
| `ORIGENS_PERMITIDAS`  | `https://SEU-USUARIO.github.io`                           |
| `ADMIN_EMAIL`         | Seu e-mail institucional                                  |
| `ADMIN_SENHA_INICIAL` | Senha forte para o primeiro acesso                        |
| `SIGCAR_USUARIO`      | E-mail do SIGCAR                                          |
| `SIGCAR_SENHA`        | Senha do SIGCAR                                           |
| `SIGAM_USUARIO`       | CPF (sem pontos) para o SIGAM                             |
| `SIGAM_SENHA`         | Senha do SIGAM                                            |

### 4. Ajuste a URL da API no index.html

No arquivo `index.html`, localize a linha:

```javascript
: 'https://naturatins-parecer.onrender.com';
```

Substitua pela URL real gerada pelo Render (visível no painel após o deploy).

### 5. Hospede o HTML no GitHub Pages

- Vá em Settings → Pages → Source: `main` / `/ (root)` → Save
- Acesse: `https://SEU-USUARIO.github.io/naturatins-parecer/`

---

## Primeiro acesso

1. O sistema cria o admin automaticamente no primeiro boot
2. Use o e-mail e senha definidos em `ADMIN_EMAIL` e `ADMIN_SENHA_INICIAL`
3. Faça login e vá em **⚙️ Admin → Usuários** para criar as contas dos analistas
4. Cada analista recebe um e-mail e senha para acessar o sistema

---

## Uso local (desenvolvimento)

```bash
pip install -r requirements.txt

# Configure as variáveis de ambiente
export SIGCAR_USUARIO="email@naturatins.to.gov.br"
export SIGCAR_SENHA="suasenha"
export SIGAM_USUARIO="cpfsempontos"
export SIGAM_SENHA="suasenha"
export FLASK_ENV="development"
export ADMIN_SENHA_INICIAL="SenhaForte123!"

python app.py
```

Abra o `index.html` diretamente no navegador (ou via Live Server no VS Code).

---

## Gerenciamento de usuários (painel admin)

Após login com perfil **admin**, clique em **⚙️ Admin**:

- **Usuários** — lista todos, ativa/desativa contas
- **Novo Usuário** — cria conta de analista ou admin
- **Logs** — histórico de todos os acessos e ações
- **Pareceres** — todos os pareceres gerados com data e analista

---

## Notas de segurança importantes

- **Troque a senha do admin** imediatamente após o primeiro login
- **Nunca** suba credenciais no código — use sempre variáveis de ambiente
- O banco PostgreSQL do Render gratuito tem 256 MB — suficiente para anos de uso
- Use `JWT_EXPIRES_HORAS=8` para sessões de 1 turno de trabalho
- O plano gratuito do Render **dorme após 15 min** sem uso (upgrade US$7/mês elimina isso)
