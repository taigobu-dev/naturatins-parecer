"""
NATURATINS – Gerador de Parecer Técnico
API Flask com autenticação JWT, banco PostgreSQL e segurança profissional.
Deploy: Render.com
"""

import os, re, time, logging, secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import jwt

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# ═══════════════════════════════════════════════════════════════════
#  CONFIGURAÇÃO
# ═══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("naturatins")

app = Flask(__name__)

# ── Segurança ────────────────────────────────────────────────────
# JWT_SECRET deve ser uma string longa e aleatória definida no Render.
# Gere com: python -c "import secrets; print(secrets.token_hex(64))"
JWT_SECRET      = os.environ.get("JWT_SECRET", secrets.token_hex(64))
JWT_EXPIRES_H   = int(os.environ.get("JWT_EXPIRES_HORAS", "8"))   # token expira em N horas
ADMIN_EMAIL     = os.environ.get("ADMIN_EMAIL", "admin@naturatins.to.gov.br")
ADMIN_SENHA_INI = os.environ.get("ADMIN_SENHA_INICIAL", "")        # só usado no primeiro boot

# ── Banco de dados ───────────────────────────────────────────────
# No Render: Settings → Environment → DATABASE_URL (gerado automaticamente)
DB_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///naturatins_dev.db"    # SQLite para desenvolvimento local
)
# Render usa "postgres://" mas SQLAlchemy precisa de "postgresql://"
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"]        = DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"]      = {
    "pool_pre_ping": True,
    "pool_recycle":  300,
}

db = SQLAlchemy(app)

# ── CORS restrito ─────────────────────────────────────────────────
# Defina ORIGENS_PERMITIDAS no Render com a URL do seu GitHub Pages
# Ex: "https://meuusuario.github.io,http://127.0.0.1:5500"
_origens_raw = os.environ.get(
    "ORIGENS_PERMITIDAS",
    "http://127.0.0.1:3000,http://127.0.0.1:5500,http://localhost:5500"
)
ORIGENS_PERMITIDAS = [o.strip() for o in _origens_raw.split(",") if o.strip()]

CORS(app,
     origins=ORIGENS_PERMITIDAS,
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
     expose_headers=["Content-Type", "Authorization"])

# ── Rate limiting (proteção contra força bruta / DDoS) ───────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

# ── Credenciais dos sistemas externos ───────────────────────────
SIGCAR_USUARIO = os.environ.get("SIGCAR_USUARIO", "")
SIGCAR_SENHA   = os.environ.get("SIGCAR_SENHA",   "")
SIGAM_USUARIO  = os.environ.get("SIGAM_USUARIO",  "")
SIGAM_SENHA    = os.environ.get("SIGAM_SENHA",    "")
SIGAM_BASE     = "https://sigam.to.gov.br/proton"


# ═══════════════════════════════════════════════════════════════════
#  MODELOS DO BANCO DE DADOS
# ═══════════════════════════════════════════════════════════════════

class Usuario(db.Model):
    """Analistas e administradores com acesso ao sistema."""
    __tablename__ = "usuarios"

    id            = db.Column(db.Integer, primary_key=True)
    nome          = db.Column(db.String(120), nullable=False)
    email         = db.Column(db.String(180), unique=True, nullable=False, index=True)
    senha_hash    = db.Column(db.String(256), nullable=False)
    perfil        = db.Column(db.String(20), nullable=False, default="analista")  # analista | admin
    ativo         = db.Column(db.Boolean, nullable=False, default=True)
    criado_em     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ultimo_acesso = db.Column(db.DateTime, nullable=True)
    tentativas_login = db.Column(db.Integer, default=0)   # bloqueia após 5 falhas
    bloqueado_ate    = db.Column(db.DateTime, nullable=True)

    pareceres = db.relationship("Parecer", backref="autor", lazy=True)
    logs      = db.relationship("LogAcesso", backref="usuario", lazy=True)

    def verificar_senha(self, senha: str) -> bool:
        return bcrypt.checkpw(senha.encode(), self.senha_hash.encode())

    def definir_senha(self, senha: str) -> None:
        self.senha_hash = bcrypt.hashpw(
            senha.encode(), bcrypt.gensalt(rounds=12)
        ).decode()

    def esta_bloqueado(self) -> bool:
        if self.bloqueado_ate and self.bloqueado_ate > datetime.now(timezone.utc):
            return True
        return False

    def registrar_falha(self) -> None:
        self.tentativas_login = (self.tentativas_login or 0) + 1
        if self.tentativas_login >= 5:
            self.bloqueado_ate = datetime.now(timezone.utc) + timedelta(minutes=30)
            log.warning("Usuário %s bloqueado por 30 min após 5 tentativas.", self.email)

    def resetar_tentativas(self) -> None:
        self.tentativas_login = 0
        self.bloqueado_ate    = None

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "nome":       self.nome,
            "email":      self.email,
            "perfil":     self.perfil,
            "ativo":      self.ativo,
            "criado_em":  self.criado_em.isoformat() if self.criado_em else None,
            "ultimo_acesso": self.ultimo_acesso.isoformat() if self.ultimo_acesso else None,
        }


class Parecer(db.Model):
    """Registro de cada parecer gerado — auditoria completa."""
    __tablename__ = "pareceres"

    id             = db.Column(db.Integer, primary_key=True)
    usuario_id     = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    numero_processo= db.Column(db.String(50))
    numero_req     = db.Column(db.String(50))
    num_parecer    = db.Column(db.String(50))
    requerente     = db.Column(db.String(200))
    municipio      = db.Column(db.String(100))
    conclusao      = db.Column(db.String(30))   # FAVORAVELMENTE | DESFAVORAVELMENTE
    criado_em      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ip_origem      = db.Column(db.String(50))

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "numero_processo": self.numero_processo,
            "numero_req":      self.numero_req,
            "num_parecer":     self.num_parecer,
            "requerente":      self.requerente,
            "municipio":       self.municipio,
            "conclusao":       self.conclusao,
            "analista":        self.autor.nome if self.autor else "",
            "criado_em":       self.criado_em.isoformat() if self.criado_em else None,
        }


class LogAcesso(db.Model):
    """Log de todas as ações relevantes para auditoria."""
    __tablename__ = "logs_acesso"

    id          = db.Column(db.Integer, primary_key=True)
    usuario_id  = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True)
    acao        = db.Column(db.String(50))   # login | logout | busca_sigam | busca_car | etc.
    detalhe     = db.Column(db.String(500))
    ip          = db.Column(db.String(50))
    criado_em   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @staticmethod
    def registrar(acao: str, detalhe: str = "", usuario_id: int = None):
        try:
            entrada = LogAcesso(
                usuario_id=usuario_id,
                acao=acao,
                detalhe=detalhe[:500],
                ip=request.remote_addr or "",
            )
            db.session.add(entrada)
            db.session.commit()
        except Exception as exc:
            log.warning("Falha ao registrar log: %s", exc)


# ═══════════════════════════════════════════════════════════════════
#  JWT — GERAÇÃO E VALIDAÇÃO
# ═══════════════════════════════════════════════════════════════════

def _gerar_token(usuario: Usuario) -> str:
    payload = {
        "sub":    str(usuario.id),  # PyJWT 2.x exige string
        "email":  usuario.email,
        "perfil": usuario.perfil,
        "exp":    datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRES_H),
        "iat":    datetime.now(timezone.utc),
        "jti":    secrets.token_hex(16),   # ID único do token (permite revogação futura)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _validar_token(token: str) -> dict:
    """
    Decodifica e valida o JWT.
    Permite 1 hora de tolerância para tokens expirados
    (cobre o caso do servidor Render acordando após dormir).
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        # Tenta decodificar ignorando expiração
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=["HS256"],
            options={"verify_exp": False}
        )
        # Aceita se expirou há menos de 2 horas (tolerância para servidor dormindo)
        exp = payload.get("exp", 0)
        agora = datetime.now(timezone.utc).timestamp()
        if agora - exp < 7200:  # 2 horas de tolerância
            log.info("Token expirado há %.0f min — aceito por tolerância", (agora - exp) / 60)
            return payload
        raise  # Expirado há mais de 2h — rejeita


def requer_login(f):
    """Decorator que exige token JWT válido em qualquer rota."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"erro": "Token não fornecido."}), 401
        token = auth[7:]
        try:
            payload = _validar_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"erro": "Sessão expirada. Faça login novamente."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"erro": "Token inválido."}), 401

        usuario = db.session.get(Usuario, int(payload["sub"]))
        if not usuario or not usuario.ativo:
            return jsonify({"erro": "Usuário inativo ou não encontrado."}), 403

        g.usuario = usuario   # disponível em toda a requisição
        return f(*args, **kwargs)
    return wrapper


def requer_admin(f):
    """Decorator que exige perfil admin (use APÓS @requer_login)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.usuario.perfil != "admin":
            LogAcesso.registrar("acesso_negado", f.__name__, g.usuario.id)
            return jsonify({"erro": "Permissão insuficiente."}), 403
        return f(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════════
#  ROTAS DE AUTENTICAÇÃO
# ═══════════════════════════════════════════════════════════════════

@app.route("/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    try:
        dados = request.get_json(silent=True) or {}
        email = str(dados.get("email", "")).strip().lower()
        senha = str(dados.get("senha", ""))

        if not email or not senha:
            return jsonify({"erro": "E-mail e senha são obrigatórios."}), 400

        # Sanitização: e-mail não pode ter caracteres perigosos
        if not re.match(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", email):
            return jsonify({"erro": "E-mail inválido."}), 400

        usuario = Usuario.query.filter_by(email=email).first()

        # Resposta genérica para não revelar se o e-mail existe
        ERRO_CREDENCIAIS = {"erro": "E-mail ou senha incorretos."}

        if not usuario:
            LogAcesso.registrar("login_falha", f"email={email} (não encontrado)")
            return jsonify(ERRO_CREDENCIAIS), 401
    except Exception as _e_login:
        import traceback
        log.error("ERRO NO LOGIN: %s", traceback.format_exc())
        return jsonify({"erro": "Erro interno: " + str(_e_login)}), 500

    if not usuario.ativo:
        return jsonify({"erro": "Conta desativada. Contate o administrador."}), 403

    if usuario.esta_bloqueado():
        return jsonify({"erro": "Conta temporariamente bloqueada. Tente em 30 minutos."}), 429

    if not usuario.verificar_senha(senha):
        usuario.registrar_falha()
        db.session.commit()
        LogAcesso.registrar("login_falha", f"email={email}", usuario.id)
        return jsonify(ERRO_CREDENCIAIS), 401

    # Login bem-sucedido
    usuario.resetar_tentativas()
    usuario.ultimo_acesso = datetime.now(timezone.utc)
    db.session.commit()

    token = _gerar_token(usuario)
    LogAcesso.registrar("login", f"email={email}", usuario.id)
    log.info("Login: %s (%s)", usuario.email, request.remote_addr)

    return jsonify({
        "token":   token,
        "usuario": usuario.to_dict(),
        "expira_em": JWT_EXPIRES_H,
    })


@app.route("/auth/me", methods=["GET"])
@requer_login
def me():
    return jsonify({"usuario": g.usuario.to_dict()})


@app.route("/auth/logout", methods=["POST"])
@requer_login
def logout():
    LogAcesso.registrar("logout", "", g.usuario.id)
    return jsonify({"mensagem": "Logout realizado."})


@app.route("/auth/alterar-senha", methods=["POST"])
@requer_login
@limiter.limit("5 per hour")
def alterar_senha():
    dados = request.get_json(silent=True) or {}
    senha_atual = str(dados.get("senha_atual", ""))
    senha_nova  = str(dados.get("senha_nova", ""))

    if not g.usuario.verificar_senha(senha_atual):
        return jsonify({"erro": "Senha atual incorreta."}), 400

    erros = _validar_forca_senha(senha_nova)
    if erros:
        return jsonify({"erro": erros}), 400

    g.usuario.definir_senha(senha_nova)
    db.session.commit()
    LogAcesso.registrar("senha_alterada", "", g.usuario.id)
    return jsonify({"mensagem": "Senha alterada com sucesso."})


def _validar_forca_senha(senha: str) -> str:
    """Valida força da senha. Retorna string de erro ou vazio se OK."""
    if len(senha) < 10:
        return "A senha deve ter pelo menos 10 caracteres."
    if not re.search(r"[A-Z]", senha):
        return "A senha deve conter pelo menos uma letra maiúscula."
    if not re.search(r"[a-z]", senha):
        return "A senha deve conter pelo menos uma letra minúscula."
    if not re.search(r"\d", senha):
        return "A senha deve conter pelo menos um número."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;':\",./<>?]", senha):
        return "A senha deve conter pelo menos um caractere especial."
    return ""


# ═══════════════════════════════════════════════════════════════════
#  ROTAS DE ADMINISTRAÇÃO
# ═══════════════════════════════════════════════════════════════════

@app.route("/admin/usuarios", methods=["GET"])
@requer_login
@requer_admin
def listar_usuarios():
    usuarios = Usuario.query.order_by(Usuario.nome).all()
    return jsonify({"usuarios": [u.to_dict() for u in usuarios]})


@app.route("/admin/usuarios", methods=["POST"])
@requer_login
@requer_admin
@limiter.limit("20 per hour")
def criar_usuario():
    dados = request.get_json(silent=True) or {}
    nome  = str(dados.get("nome", "")).strip()
    email = str(dados.get("email", "")).strip().lower()
    senha = str(dados.get("senha", ""))
    perfil = str(dados.get("perfil", "analista"))

    if not all([nome, email, senha]):
        return jsonify({"erro": "Nome, e-mail e senha são obrigatórios."}), 400
    if perfil not in ("analista", "admin"):
        return jsonify({"erro": "Perfil inválido."}), 400
    if Usuario.query.filter_by(email=email).first():
        return jsonify({"erro": "E-mail já cadastrado."}), 409

    erros = _validar_forca_senha(senha)
    if erros:
        return jsonify({"erro": erros}), 400

    novo = Usuario(nome=nome, email=email, perfil=perfil)
    novo.definir_senha(senha)
    db.session.add(novo)
    db.session.commit()
    LogAcesso.registrar("usuario_criado", f"email={email}", g.usuario.id)
    log.info("Novo usuário criado: %s por %s", email, g.usuario.email)
    return jsonify({"mensagem": "Usuário criado.", "usuario": novo.to_dict()}), 201


@app.route("/admin/usuarios/<int:uid>", methods=["PATCH"])
@requer_login
@requer_admin
def atualizar_usuario(uid: int):
    usuario = db.session.get(Usuario, uid)
    if not usuario:
        return jsonify({"erro": "Usuário não encontrado."}), 404

    dados = request.get_json(silent=True) or {}
    if "ativo" in dados:
        usuario.ativo = bool(dados["ativo"])
    if "perfil" in dados and dados["perfil"] in ("analista", "admin"):
        usuario.perfil = dados["perfil"]
    if "nome" in dados and dados["nome"].strip():
        usuario.nome = dados["nome"].strip()

    # Não permite o admin desativar a própria conta
    if usuario.id == g.usuario.id and not usuario.ativo:
        return jsonify({"erro": "Não é possível desativar sua própria conta."}), 400

    db.session.commit()
    LogAcesso.registrar("usuario_atualizado", f"uid={uid}", g.usuario.id)
    return jsonify({"usuario": usuario.to_dict()})


@app.route("/admin/usuarios/<int:uid>/resetar-senha", methods=["POST"])
@requer_login
@requer_admin
def resetar_senha(uid: int):
    usuario = db.session.get(Usuario, uid)
    if not usuario:
        return jsonify({"erro": "Usuário não encontrado."}), 404

    dados = request.get_json(silent=True) or {}
    nova_senha = str(dados.get("senha", ""))
    erros = _validar_forca_senha(nova_senha)
    if erros:
        return jsonify({"erro": erros}), 400

    usuario.definir_senha(nova_senha)
    usuario.resetar_tentativas()
    db.session.commit()
    LogAcesso.registrar("senha_resetada", f"uid={uid}", g.usuario.id)
    return jsonify({"mensagem": "Senha redefinida com sucesso."})


@app.route("/admin/logs", methods=["GET"])
@requer_login
@requer_admin
def listar_logs():
    pagina = request.args.get("pagina", 1, type=int)
    por_pagina = 50
    logs = (LogAcesso.query
            .order_by(LogAcesso.criado_em.desc())
            .paginate(page=pagina, per_page=por_pagina, error_out=False))
    return jsonify({
        "logs": [{
            "id":       l.id,
            "acao":     l.acao,
            "detalhe":  l.detalhe,
            "ip":       l.ip,
            "usuario":  l.usuario.email if l.usuario else "–",
            "criado_em": l.criado_em.isoformat() if l.criado_em else None,
        } for l in logs.items],
        "total":   logs.total,
        "paginas": logs.pages,
        "pagina":  pagina,
    })


@app.route("/admin/pareceres", methods=["GET"])
@requer_login
@requer_admin
def listar_pareceres():
    pagina = request.args.get("pagina", 1, type=int)
    por_pagina = 50
    pareceres = (Parecer.query
                 .order_by(Parecer.criado_em.desc())
                 .paginate(page=pagina, per_page=por_pagina, error_out=False))
    return jsonify({
        "pareceres": [p.to_dict() for p in pareceres.items],
        "total":     pareceres.total,
        "paginas":   pareceres.pages,
    })


@app.route("/api/registrar-parecer", methods=["POST", "OPTIONS"])
def registrar_parecer():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    # Valida autenticação manualmente
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"erro": "Token não fornecido."}), 401
    try:
        payload = _validar_token(auth[7:])
        usuario = db.session.get(Usuario, int(payload["sub"]))
        if not usuario or not usuario.ativo:
            return jsonify({"erro": "Usuário inativo."}), 403
        g.usuario = usuario
    except jwt.InvalidTokenError:
        return jsonify({"erro": "Token inválido."}), 401
    """Salva o registro do parecer gerado no banco para auditoria."""
    dados = request.get_json(silent=True) or {}
    parecer = Parecer(
        usuario_id     = g.usuario.id,
        numero_processo= str(dados.get("numero_processo", ""))[:50],
        numero_req     = str(dados.get("numero_requerimento", ""))[:50],
        num_parecer    = str(dados.get("num_parecer", ""))[:50],
        requerente     = str(dados.get("requerente", ""))[:200],
        municipio      = str(dados.get("municipio", ""))[:100],
        conclusao      = str(dados.get("conclusao", ""))[:30],
        ip_origem      = request.remote_addr or "",
    )
    db.session.add(parecer)
    db.session.commit()
    LogAcesso.registrar("parecer_gerado",
                        f"processo={dados.get('numero_processo')} conclusao={dados.get('conclusao')}",
                        g.usuario.id)
    return jsonify({"mensagem": "Parecer registrado.", "id": parecer.id})


# ═══════════════════════════════════════════════════════════════════
#  SELENIUM — UTILITÁRIOS
# ═══════════════════════════════════════════════════════════════════

def _criar_driver() -> webdriver.Chrome:
    """
    Cria Chrome headless.
    No Render usa o Chromium instalado via Playwright (em /opt/render/.cache/ms-playwright/).
    Localmente usa o ChromeDriverManager.
    """
    import glob

    opts = webdriver.ChromeOptions()
    opts.add_argument("--headless=new")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-infobars")
    opts.add_argument("--log-level=3")

    # Procura Chrome em todos os caminhos possíveis do Render/Playwright
    caminhos_chrome_possiveis = []
    bases_busca = [
        "/opt/render/.cache/ms-playwright",
        os.path.expanduser("~/.cache/ms-playwright"),
        "/root/.cache/ms-playwright",
        os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""),
    ]
    for base in bases_busca:
        if not base or not os.path.exists(base):
            continue
        # Adiciona todos os padrões possíveis
        caminhos_chrome_possiveis.extend([
            os.path.join(base, "chromium-*/chrome-linux/chrome"),
            os.path.join(base, "chromium-*/chrome-linux64/chrome"),
            os.path.join(base, "chromium_headless_shell-*/chrome-linux/headless_shell"),
            os.path.join(base, "chromium_headless_shell-*/chrome-linux/chrome"),
        ])
        # Log do que está realmente lá
        try:
            log.info("Conteúdo de %s: %s", base, os.listdir(base))
        except Exception:
            pass

    chrome_encontrado = None
    for padrao in caminhos_chrome_possiveis:
        achados = glob.glob(padrao)
        if achados:
            chrome_encontrado = achados[0]
            log.info("Chrome encontrado: %s", chrome_encontrado)
            break

    if chrome_encontrado:
        opts.binary_location = chrome_encontrado
        # Tenta usar ChromeDriverManager mesmo com binary customizado
        try:
            driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=opts,
            )
            return driver
        except Exception as exc:
            log.warning("ChromeDriverManager falhou: %s — tentando driver padrão", exc)
            return webdriver.Chrome(options=opts)

    # Fallback completo: ChromeDriverManager sem binary location
    log.warning("Chrome do Playwright não encontrado — usando ChromeDriverManager")
    return webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=opts,
    )


def _preencher_campo(driver, campo, valor: str) -> None:
    driver.execute_script("arguments[0].value = '';", campo)
    time.sleep(0.15)
    campo.click()
    campo.send_keys(Keys.CONTROL + "a")
    campo.send_keys(Keys.DELETE)
    time.sleep(0.15)
    for ch in str(valor):
        campo.send_keys(ch)
        time.sleep(0.06)
    time.sleep(0.25)


def _entrar_frame_principal(driver) -> None:
    driver.switch_to.default_content()
    frames = driver.find_elements(By.TAG_NAME, "frame") or \
             driver.find_elements(By.TAG_NAME, "iframe")
    if not frames:
        return
    for nome in ("main", "conteudo", "content", "MAIN", "corpo"):
        try:
            driver.switch_to.frame(nome)
            return
        except Exception:
            pass
    try:
        driver.switch_to.frame(frames[0])
    except Exception:
        pass


def _obter_texto_pagina(driver) -> str:
    MARCADORES = (
        "RESPONSÁVEL TÉCNICO:",
        "RESPONSAVEL TECNICO:",
        "IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO",
    )
    def _tem_rt(txt: str) -> bool:
        return any(m in txt for m in MARCADORES)

    try:
        texto = driver.find_element(By.TAG_NAME, "body").text
    except Exception:
        texto = ""

    if _tem_rt(texto):
        return texto

    for tag in ("frame", "iframe"):
        for fr in driver.find_elements(By.TAG_NAME, tag):
            try:
                driver.switch_to.frame(fr)
                ft = driver.find_element(By.TAG_NAME, "body").text
                driver.switch_to.default_content()
                if _tem_rt(ft):
                    return ft
            except Exception:
                try:
                    driver.switch_to.default_content()
                except Exception:
                    pass
    return texto


def _extrair_rt_do_texto(body_text: str) -> dict:
    if not body_text:
        return {}
    RT_MARCADORES = (
        "RESPONSÁVEL TÉCNICO", "RESPONSAVEL TECNICO",
        "IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO",
    )
    if not any(m in body_text.upper() for m in RT_MARCADORES):
        return {}

    def _linha_apos(marcador: str, texto: str) -> str:
        idx = texto.find(marcador)
        if idx < 0:
            return ""
        linhas = [l.strip() for l in texto[idx + len(marcador):].split("\n") if l.strip()]
        return linhas[0] if linhas else ""

    nome_req = cpf_req = ""
    for mk in ("REQUERENTE:", "Requerente:"):
        linha = _linha_apos(mk, body_text)
        if linha:
            partes = linha.split(" - CPF:")
            nome_req = partes[0].strip()
            if len(partes) > 1:
                cpf_req = partes[1].split(" - ")[0].strip()
            break

    nome_rt = cpf_rt = email_rt = tel_rt = formacao = registro = ""
    for mk in ("RESPONSÁVEL TÉCNICO:", "RESPONSAVEL TECNICO:",
               "RESPONSÁVEL TÉCNICO",  "RESPONSAVEL TECNICO"):
        linha = _linha_apos(mk, body_text)
        if linha:
            partes = linha.split(" - CPF:")
            nome_rt = partes[0].strip()
            if len(partes) > 1:
                resto = partes[1]
                cpf_rt   = resto.split(" - ")[0].strip()
                m = re.search(r"E-MAIL[:\s]+([^\s\n]+)", resto, re.IGNORECASE)
                email_rt = m.group(1).strip() if m else ""
                m = re.search(r"TELEFONE[:\s]+([^\-\n]+)", resto, re.IGNORECASE)
                tel_rt   = m.group(1).strip() if m else ""
            break

    if not nome_rt:
        mk_ant = "IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO"
        if mk_ant in body_text:
            secao = body_text[body_text.index(mk_ant):]
            fim = secao.find("DADOS DO ENQUADRAMENTO")
            if fim > 0:
                secao = secao[:fim]
            def _achar(p):
                m = re.search(p, secao, re.IGNORECASE)
                return m.group(1).strip() if m else ""
            nome_rt  = _achar(r"Nome/Raz[aã]o social\s*:?\s*\n\s*([^\n]+)")
            cpf_rt   = _achar(r"CPF/CNPJ\s*:?\s*\n\s*([^\n]+)")
            tel_rt   = _achar(r"Telefone\s*:?\s*\n\s*([^\n]+)")
            email_rt = _achar(r"E-mail\s*:?\s*\n\s*([^\n]+)")
            formacao = _achar(r"Forma[çc][aã]o Profissional\s*[:\-]\s*([^\n|\-]+)")
            registro = _achar(r"Registro Profissional\s*[:\-]\s*([^\n]+)")

    if not formacao:
        m = re.search(r"Forma[çc][aã]o Profissional\s*[:\-]\s*([^\n|\-]+)", body_text, re.IGNORECASE)
        if m: formacao = m.group(1).strip()
    if not registro:
        m = re.search(r"Registro Profissional\s*[:\-]\s*([^\n]+)", body_text, re.IGNORECASE)
        if m: registro = m.group(1).strip()

    if not nome_rt and not cpf_rt:
        return {}

    num_req = ""
    for padrao in [
        r"REQUERIMENTO\s+([\d][\d\-/]+[\d])",
        r"N[\u00ba\u00b0]\s*:?\s*([\d]+/\d{4})",
        r"IDENTIFICAÇÃO[:\s]+([\d][\d\-/]+[\d])",
        r"ORIGEM[:\s]+([\d]+/\d{4})",
        r"REFERÊNCIA[:\s]+([\d]+/\d{4})",
    ]:
        m = re.search(padrao, body_text, re.IGNORECASE)
        if m:
            num_req = m.group(1).strip()
            break

    resultado = {
        "resp_tecnico_nome":     nome_rt,
        "resp_tecnico_cpf":      cpf_rt,
        "resp_tecnico_tel":      tel_rt,
        "resp_tecnico_email":    email_rt,
        "resp_tecnico_formacao": formacao,
        "resp_tecnico_registro": registro,
    }
    if num_req:  resultado["num_requerimento_doc"] = num_req
    if nome_req: resultado["nome_requerente_doc"]  = nome_req
    if cpf_req:  resultado["cpf_requerente_doc"]   = cpf_req
    return resultado


def _extrair_rt_driver(driver) -> dict:
    try:
        texto = _obter_texto_pagina(driver)
        if not texto:
            return {}
        resultado = _extrair_rt_do_texto(texto)
        if resultado:
            log.info("  RT: %s | %s",
                     resultado.get("resp_tecnico_nome", ""),
                     resultado.get("resp_tecnico_cpf", ""))
        return resultado
    except Exception as exc:
        log.warning("  Erro RT: %s", exc)
        return {}


def _varrer_frames_rt(driver) -> dict:
    resultado = _extrair_rt_driver(driver)
    if resultado:
        return resultado
    for tag in ("frame", "iframe"):
        for fr in driver.find_elements(By.TAG_NAME, tag):
            try:
                driver.switch_to.frame(fr)
                resultado = _extrair_rt_driver(driver)
                if resultado:
                    driver.switch_to.default_content()
                    return resultado
                for tag2 in ("frame", "iframe"):
                    for sf in driver.find_elements(By.TAG_NAME, tag2):
                        try:
                            driver.switch_to.frame(sf)
                            resultado = _extrair_rt_driver(driver)
                            if resultado:
                                driver.switch_to.default_content()
                                return resultado
                            driver.switch_to.parent_frame()
                        except Exception:
                            try: driver.switch_to.parent_frame()
                            except Exception: pass
                driver.switch_to.default_content()
            except Exception:
                try: driver.switch_to.default_content()
                except Exception: pass
    return {}


# ═══════════════════════════════════════════════════════════════════
#  ROTAS SIGCAR (PROTEGIDAS)
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/buscar-car", methods=["POST", "OPTIONS"])
@limiter.limit("30 per hour")
def buscar_car():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    # Valida autenticação manualmente (OPTIONS não passa pelo decorator)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"erro": "Token não fornecido."}), 401
    try:
        payload = _validar_token(auth[7:])
        usuario = db.session.get(Usuario, int(payload["sub"]))
        if not usuario or not usuario.ativo:
            return jsonify({"erro": "Usuário inativo."}), 403
    except jwt.InvalidTokenError:
        return jsonify({"erro": "Token inválido."}), 401

    driver = None
    try:
        numero_car = (request.json or {}).get("car", "")
        if not numero_car:
            return jsonify({"sucesso": False, "mensagem": "Número do CAR não informado."})

        LogAcesso.registrar("busca_car", f"car={numero_car}", usuario.id)
        log.info("CAR: %s — por %s", numero_car, usuario.email)
        driver = _criar_driver()
        wait   = WebDriverWait(driver, 20)

        def _texto(xpath, timeout=6) -> str:
            try:
                el = WebDriverWait(driver, timeout).until(
                    EC.presence_of_element_located((By.XPATH, xpath)))
                txt = el.text.strip() or el.get_attribute("value") or \
                      el.get_attribute("innerHTML") or ""
                return re.sub(r"<[^>]+>", "", str(txt)).strip()
            except Exception:
                return ""

        def _td2(id_el, timeout=6) -> str:
            return _texto(f'//*[@id="{id_el}"]/td[2]', timeout)

        def _num(texto) -> float:
            if not texto or str(texto).strip() in ("-", ""):
                return 0.0
            try:
                t = re.sub(r"<[^>]+>", "", str(texto)).strip()
                t = re.sub(r"\(.*?\)", "", t.lower().replace("ha", "")).strip()
                return float(t.replace(".", "").replace(",", ".")) if t else 0.0
            except Exception:
                return 0.0

        def _pct(texto) -> str:
            m = re.search(r"([\d,]+)\s*%", texto)
            return (m.group(1).replace(",", ".") + "%") if m else ""

        driver.get("http://sigcar.semarh.to.gov.br/")
        wait.until(EC.presence_of_element_located((By.ID, "email"))).send_keys(SIGCAR_USUARIO)
        driver.find_element(By.ID, "senha").send_keys(SIGCAR_SENHA)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(2)

        driver.get("http://sigcar.semarh.to.gov.br/imovel/consultar/inicio.jhtml")
        wait.until(EC.presence_of_element_located((By.ID, "codigoCar"))).send_keys(numero_car)
        driver.find_element(By.ID, "buscarButton").click()
        time.sleep(3)

        status_car  = _texto('//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[3]/b')
        municipio   = _texto('//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[5]')
        nome_imovel = _texto('//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[2]')

        wait.until(EC.element_to_be_clickable(
            (By.XPATH, '//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[1]')
        )).click()
        time.sleep(4)

        for nav_xpath in [
            '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[1]/ul/li[1]/a',
        ]:
            btn = wait.until(EC.presence_of_element_located((By.XPATH, nav_xpath)))
            driver.execute_script("arguments[0].click();", btn)
            time.sleep(3)
            break

        area_escriturada = _num(_texto(
            '//*[@id="MAIN"]/section/div[1]/article/div[3]/article/section[4]/div/section/div/strong'))

        btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[1]/ul/li[3]/a')))
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(3)
        data_sigcar = _texto(
            '//*[@id="MAIN"]/section/div[1]/article/section[3]/section[2]/table[1]/tbody/tr[1]/td[2]')

        btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[2]/ul/li[3]/a')))
        driver.execute_script("arguments[0].click();", btn)
        try:
            wait.until(EC.presence_of_element_located((By.XPATH, '//*[@id="tabela_ficha_pf"]')))
            time.sleep(2)
        except Exception:
            pass
        nome_req = _texto('//*[@id="tabela_ficha_pf"]/tbody/tr[1]/td[1]/div')
        cpf_req  = _texto('//*[@id="tabela_ficha_pf"]/tbody/tr[1]/td[2]')

        btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[1]/ul/li[5]/a')))
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(6)

        return jsonify({
            "sucesso": True,
            "nome_requerente":         nome_req,
            "cpf_requerente":          cpf_req,
            "status_car":              status_car,
            "municipio":               municipio,
            "denominacao_imovel":      nome_imovel,
            "data_sigcar":             data_sigcar,
            "area_escriturada":        area_escriturada,
            "area_vetorizada":         _num(_td2("areaImovel", 10)),
            "area_liquida":            _num(_td2("areaImovelLiquida", 10)),
            "remanescente":            _num(_td2("vegetacaoNativa")),
            "consolidada":             _num(_td2("areaConsolidada")),
            "antropizada":             _num(_td2("areaAntropizadaApos22072008")),
            "uso_alternativo":         _num(_td2("areaUsoAlternativo")),
            "pousio":                  _num(_td2("areaPousio")),
            "infra_publica":           _num(_td2("areaInfraPublica")),
            "utilidade_publica":       _num(_td2("areaUtilidadePublica")),
            "servidao":                _num(_td2("areaServidaoAdm")),
            "app":                     _num(_td2("appGeral")),
            "app_61a":                 _num(_td2("appEscadinha")),
            "app_a_recuperar":         _num(_td2("appDegradada")),
            "reserva_legal":           _num(_td2("arlProposta")),
            "reserva_legal_pct":       _pct(_texto('//*[@id="arlProposta"]')),
            "suplementar":             _num(_td2("arlSuplementar")),
            "rl_a_recuperar":          _num(_td2("arlDegradada")),
            "reserva_legal_total":     _num(_td2("arlTotal")),
            "reserva_legal_total_pct": _pct(_texto('//*[@id="arlTotal"]')),
            "arl_com_vegetacao":       _num(_td2("arlComVegetacao")),
        })

    except Exception as exc:
        log.error("CAR erro: %s", exc)
        return jsonify({"sucesso": False, "mensagem": str(exc)})
    finally:
        if driver:
            driver.quit()


# ═══════════════════════════════════════════════════════════════════
#  ROTAS SIGAM (PROTEGIDAS)
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/buscar-sigam", methods=["POST", "OPTIONS"])
def buscar_sigam():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    auth = request.headers.get("Authorization", "")
    log.info("SIGAM auth header (primeiros 30 chars): %s", auth[:30] if auth else "VAZIO")
    if not auth.startswith("Bearer "):
        log.warning("SIGAM: token não enviado ou formato inválido")
        return jsonify({"erro": "Token não fornecido."}), 401
    token_str = auth[7:]
    log.info("SIGAM token (primeiros 30 chars): %s", token_str[:30])
    try:
        payload  = _validar_token(token_str)
        log.info("SIGAM token válido para usuário id=%s", int(payload.get("sub", 0)) if payload.get("sub") else None)
        usuario  = db.session.get(Usuario, int(payload["sub"]))
        if not usuario or not usuario.ativo:
            log.warning("SIGAM: usuário não encontrado ou inativo")
            return jsonify({"erro": "Usuário inativo."}), 403
    except jwt.InvalidTokenError as e:
        log.error("SIGAM token rejeitado: %s", e)
        return jsonify({"erro": "Token inválido: " + str(e)}), 401
    except Exception as e:
        log.error("SIGAM erro inesperado na auth: %s", e)
        return jsonify({"erro": "Erro de autenticação: " + str(e)}), 401

    driver = None
    try:
        dados      = request.json or {}
        ano        = str(dados.get("ano", "")).strip()
        orgao      = str(dados.get("orgao", "")).strip()
        sequencial = str(dados.get("sequencial", "")).strip()

        if not all([ano, orgao, sequencial]):
            return jsonify({"sucesso": False, "mensagem": "Informe Ano, Órgão e Sequencial."})

        LogAcesso.registrar("busca_sigam", f"{ano}/{orgao}/{sequencial}", usuario.id)
        log.info("SIGAM: %s/%s/%s — por %s", ano, orgao, sequencial, usuario.email)
        driver = _criar_driver()
        wait   = WebDriverWait(driver, 30)

        driver.get(f"{SIGAM_BASE}/login.asp")
        wait.until(EC.presence_of_element_located((By.NAME, "txt_login"))).send_keys(SIGAM_USUARIO)
        driver.find_element(By.NAME, "txt_senha").send_keys(SIGAM_SENHA)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        wait.until(lambda d: "login.asp" not in d.current_url)
        time.sleep(3)
        _entrar_frame_principal(driver)

        wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="processo"]/span'))).click()
        time.sleep(2)
        wait.until(EC.element_to_be_clickable(
            (By.XPATH, '//*[@id="sidebar-wrapper"]/div[3]/div/ul/li[9]/ul/li[5]/a')
        )).click()
        time.sleep(3)

        _preencher_campo(driver,
            wait.until(EC.presence_of_element_located((By.XPATH, '//*[@id="txt_numero_ano"]'))), ano)
        _preencher_campo(driver,
            driver.find_element(By.XPATH, '//*[@id="txt_numero_orgao"]'), orgao)
        _preencher_campo(driver,
            driver.find_element(By.XPATH, '//*[@id="txt_numero_sequencial"]'), sequencial)

        driver.find_element(By.XPATH, '//*[@id="wrapper"]/div[3]/div/div/div/form').submit()
        time.sleep(5)

        try:
            alert = driver.switch_to.alert
            msg = alert.text
            alert.accept()
            return jsonify({"sucesso": False, "mensagem": msg})
        except Exception:
            pass

        url_submit = driver.current_url
        m = re.search(r"cod_protocolo=(\d+)", url_submit)
        cod_protocolo = m.group(1) if m else ""

        numero_processo = ""
        driver.switch_to.default_content()
        for xp in ('//*[@id="wrapper"]/div[3]/div/div/div/table/tbody/tr[2]', '//table/tbody/tr[2]'):
            try:
                txt = driver.find_element(By.XPATH, xp).text.strip()
                m2  = re.match(r"(\d{4}/\d+/\d+)", txt)
                if m2:
                    numero_processo = m2.group(1)
                    break
            except Exception:
                pass

        if not numero_processo and cod_protocolo:
            numero_processo = f"(cod={cod_protocolo})"

        if not cod_protocolo:
            raise RuntimeError(f"cod_protocolo não encontrado: {url_submit}")

        # Coleta documentos juntados
        ACOES = ("alterar.asp", "assinar.asp", "cancelar.asp", "distribuir.asp",
                 "movimentar.asp", "comentar.asp", "vincular.asp", "pendencia.asp",
                 "responder.asp", "enquadramento.asp", "arquivar.asp")

        def _coletar_docs() -> list:
            candidatos, vistos = [], set()
            def _varrer():
                try:
                    for a in driver.find_elements(By.XPATH, "//a[@href]"):
                        href = (a.get_attribute("href") or "").strip()
                        txt  = a.text.strip()
                        mc = re.search(r"cod_protocolo=(\d+)", href)
                        if not mc: continue
                        cp = mc.group(1)
                        if cp == cod_protocolo or cp in vistos: continue
                        if any(ac in href.lower() for ac in ACOES): continue
                        vistos.add(cp)
                        candidatos.append((txt, href, cp))
                except Exception: pass

            driver.switch_to.default_content()
            _varrer()
            for tag in ("frame", "iframe"):
                for fr in driver.find_elements(By.TAG_NAME, tag):
                    try:
                        driver.switch_to.frame(fr)
                        _varrer()
                        for sf in (driver.find_elements(By.TAG_NAME, "frame") +
                                   driver.find_elements(By.TAG_NAME, "iframe")):
                            try:
                                driver.switch_to.frame(sf)
                                _varrer()
                                driver.switch_to.parent_frame()
                            except Exception:
                                try: driver.switch_to.parent_frame()
                                except Exception: pass
                        driver.switch_to.default_content()
                    except Exception:
                        try: driver.switch_to.default_content()
                        except Exception: pass
            return candidatos

        docs_juntados = _coletar_docs()
        cp_ultimo = docs_juntados[-1][2] if docs_juntados else ""
        numero_requerimento = (docs_juntados[-1][0] or f"cod={cp_ultimo}") if docs_juntados else ""

        visitados_rt: set = set()

        def _buscar_rt(cp: str, nivel: int = 0) -> dict:
            if not cp or nivel > 3 or cp in visitados_rt:
                return {}
            visitados_rt.add(cp)

            for url in [
                f"{SIGAM_BASE}/protocolo/impressao.asp?cod_protocolo={cp}&area=documento",
                f"{SIGAM_BASE}/protocolo/impressao_processo.asp?cod_protocolo={cp}&area=processo",
            ]:
                driver.switch_to.default_content()
                driver.get(url)
                time.sleep(5)
                rt = _varrer_frames_rt(driver)
                if rt:
                    return rt
                filhos, vistos_f = [], set()
                try:
                    for a in driver.find_elements(By.XPATH, "//a[@href]"):
                        href = (a.get_attribute("href") or "").strip()
                        mc = re.search(r"cod_protocolo=(\d+)", href)
                        if not mc: continue
                        cf = mc.group(1)
                        if cf in (cp, cod_protocolo) or cf in vistos_f: continue
                        if any(ac in href.lower() for ac in ACOES): continue
                        vistos_f.add(cf); filhos.append(cf)
                except Exception: pass
                for cf in reversed(filhos):
                    rt = _buscar_rt(cf, nivel + 1)
                    if rt: return rt
            return {}

        dados_rt = _buscar_rt(cp_ultimo) if cp_ultimo else {}

        num_req_final = dados_rt.get("num_requerimento_doc", "")
        if not num_req_final and docs_juntados:
            cp_primeiro = docs_juntados[0][2]
            try:
                driver.switch_to.default_content()
                driver.get(f"{SIGAM_BASE}/protocolo/impressao.asp?cod_protocolo={cp_primeiro}&area=documento")
                time.sleep(4)
                txt_orig = _obter_texto_pagina(driver)
                if txt_orig:
                    for padrao in [
                        r"REQUERIMENTO\s+([\d][\d\-/]+[\d])",
                        r"N[\u00ba\u00b0]\s*:?\s*([\d]+/\d{4})",
                        r"IDENTIFICAÇÃO[:\s]+([\d][\d\-/]+[\d])",
                        r"ORIGEM[:\s]+([\d]+/\d{4})",
                    ]:
                        m3 = re.search(padrao, txt_orig, re.IGNORECASE)
                        if m3:
                            num_req_final = m3.group(1).strip()
                            break
            except Exception as exc:
                log.warning("Nº req: %s", exc)

        if num_req_final:
            dados_rt["num_requerimento_doc"] = num_req_final

        log.info("SIGAM OK: proc=%s RT=%s", numero_processo, bool(dados_rt))
        return jsonify({
            "sucesso":             True,
            "numero_processo":     numero_processo,
            "numero_requerimento": numero_requerimento,
            **dados_rt,
        })

    except Exception as exc:
        log.error("SIGAM erro: %s", exc)
        return jsonify({"sucesso": False, "mensagem": str(exc)})
    finally:
        if driver:
            driver.quit()


# ═══════════════════════════════════════════════════════════════════
#  HEALTHCHECK
# ═══════════════════════════════════════════════════════════════════

# Garante que o banco é inicializado quando o servidor acorda
# Roda uma única vez na primeira requisição após restart
_banco_inicializado = False

@app.before_request
def garantir_banco():
    global _banco_inicializado
    if not _banco_inicializado:
        try:
            _inicializar_banco()
            _banco_inicializado = True
            log.info("Banco inicializado automaticamente.")
        except Exception as e:
            log.error("Erro ao inicializar banco: %s", e)
            # Não bloqueia a requisição — tenta continuar mesmo com erro no banco


@app.route("/init-db", methods=["GET"])
def init_db_manual():
    """Rota para forçar a inicialização do banco manualmente se necessário."""
    try:
        _inicializar_banco()
        return jsonify({"status": "ok", "mensagem": "Banco inicializado com sucesso."})
    except Exception as e:
        return jsonify({"status": "erro", "mensagem": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "naturatins-parecer"})



# ═══════════════════════════════════════════════════════════════════
#  HEADERS DE SEGURANÇA (aplicados em todas as respostas)
# ═══════════════════════════════════════════════════════════════════

@app.after_request
def aplicar_headers_seguranca(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]            = "DENY"
    response.headers["X-XSS-Protection"]           = "1; mode=block"
    response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"]  = "max-age=31536000; includeSubDomains"
    # Remove cabeçalho que revela tecnologia
    response.headers.pop("Server", None)
    return response


# ═══════════════════════════════════════════════════════════════════
#  INICIALIZAÇÃO DO BANCO E ADMIN PADRÃO
# ═══════════════════════════════════════════════════════════════════

def _inicializar_banco():
    """Cria as tabelas e o usuário admin inicial se não existir."""
    db.create_all()
    admin = Usuario.query.filter_by(email=ADMIN_EMAIL).first()
    if not admin:
        senha = ADMIN_SENHA_INI or secrets.token_urlsafe(16)
        admin = Usuario(nome="Administrador", email=ADMIN_EMAIL, perfil="admin")
        admin.definir_senha(senha)
        db.session.add(admin)
        db.session.commit()
        if not ADMIN_SENHA_INI:
            log.warning("=" * 60)
            log.warning("ADMIN CRIADO — SENHA GERADA AUTOMATICAMENTE:")
            log.warning("E-mail: %s", ADMIN_EMAIL)
            log.warning("Senha:  %s", senha)
            log.warning("ALTERE ESTA SENHA IMEDIATAMENTE APÓS O PRIMEIRO LOGIN.")
            log.warning("=" * 60)
        else:
            log.info("Admin inicial criado: %s", ADMIN_EMAIL)


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    with app.app_context():
        _inicializar_banco()
    port  = int(os.environ.get("PORT", 3000))
    debug = os.environ.get("FLASK_ENV", "production") == "development"
    log.info("Iniciando servidor — porta %d | debug=%s", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
