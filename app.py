"""
NATURATINS – Gerador de Parecer Técnico
API Flask com autenticação JWT, banco PostgreSQL e segurança profissional.
Deploy: Render.com — SEM Selenium, usa requests puro.
"""

import os, re, time, logging, secrets, base64
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import jwt
import requests as req
from bs4 import BeautifulSoup

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

JWT_SECRET      = os.environ.get("JWT_SECRET", secrets.token_hex(64))
JWT_EXPIRES_H   = int(os.environ.get("JWT_EXPIRES_HORAS", "8"))
ADMIN_EMAIL     = os.environ.get("ADMIN_EMAIL", "admin@naturatins.to.gov.br")
ADMIN_SENHA_INI = os.environ.get("ADMIN_SENHA_INICIAL", "")

DB_URL = os.environ.get("DATABASE_URL", "sqlite:///naturatins_dev.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"]        = DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"]      = {
    "pool_pre_ping": True,
    "pool_recycle":  300,
}

db = SQLAlchemy(app)

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

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

SIGCAR_USUARIO = os.environ.get("SIGCAR_USUARIO", "")
SIGCAR_SENHA   = os.environ.get("SIGCAR_SENHA",   "")
SIGAM_USUARIO  = os.environ.get("SIGAM_USUARIO",  "")
SIGAM_SENHA    = os.environ.get("SIGAM_SENHA",    "")
SIGAM_BASE     = "https://sigam.to.gov.br/proton"

# Proxy local (computador dentro da rede NATURATINS)
# Se definido, todas as requisições ao SIGAM passam pelo proxy
SIGAM_PROXY_URL   = os.environ.get("SIGAM_PROXY_URL",   "")  # ex: http://192.168.1.100:5050
SIGAM_PROXY_CHAVE = os.environ.get("SIGAM_PROXY_CHAVE", "naturatins-proxy-2026")
SIGCAR_BASE    = "http://sigcar.semarh.to.gov.br"

# E-mail via API HTTP do Brevo (não usa SMTP — funciona no Render gratuito)
BREVO_API_KEY   = os.environ.get("BREVO_API_KEY",  "")
EMAIL_REMETENTE = os.environ.get("EMAIL_REMETENTE", "")
FRONTEND_URL    = os.environ.get("FRONTEND_URL",    "https://taigobu-dev.github.io/naturatins-parecer")

# Anthropic Claude API — leitura de certidões
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"


# ═══════════════════════════════════════════════════════════════════
#  MODELOS DO BANCO DE DADOS
# ═══════════════════════════════════════════════════════════════════

class Usuario(db.Model):
    __tablename__ = "usuarios"

    id            = db.Column(db.Integer, primary_key=True)
    nome          = db.Column(db.String(120), nullable=False)
    email         = db.Column(db.String(180), unique=True, nullable=False, index=True)
    senha_hash    = db.Column(db.String(256), nullable=False)
    perfil        = db.Column(db.String(20), nullable=False, default="analista")
    ativo         = db.Column(db.Boolean, nullable=False, default=True)
    criado_em     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ultimo_acesso = db.Column(db.DateTime, nullable=True)
    tentativas_login  = db.Column(db.Integer, default=0)
    bloqueado_ate     = db.Column(db.DateTime, nullable=True)
    reset_token       = db.Column(db.String(128), nullable=True, index=True)
    reset_token_expira = db.Column(db.DateTime, nullable=True)

    pareceres = db.relationship("Parecer", backref="autor", lazy=True)
    logs      = db.relationship("LogAcesso", backref="usuario", lazy=True)

    def verificar_senha(self, senha: str) -> bool:
        return bcrypt.checkpw(senha.encode(), self.senha_hash.encode())

    def definir_senha(self, senha: str) -> None:
        self.senha_hash = bcrypt.hashpw(
            senha.encode(), bcrypt.gensalt(rounds=12)
        ).decode()

    def esta_bloqueado(self) -> bool:
        if not self.bloqueado_ate:
            return False
        bloqueado = self.bloqueado_ate
        if bloqueado.tzinfo is None:
            bloqueado = bloqueado.replace(tzinfo=timezone.utc)
        return bloqueado > datetime.now(timezone.utc)

    def registrar_falha(self) -> None:
        self.tentativas_login = (self.tentativas_login or 0) + 1
        if self.tentativas_login >= 5:
            self.bloqueado_ate = datetime.now(timezone.utc) + timedelta(minutes=30)
            log.warning("Usuário %s bloqueado por 30 min após 5 tentativas.", self.email)

    def resetar_tentativas(self) -> None:
        self.tentativas_login = 0
        self.bloqueado_ate    = None

    def gerar_reset_token(self) -> str:
        token = secrets.token_urlsafe(48)
        self.reset_token        = token
        self.reset_token_expira = datetime.now(timezone.utc) + timedelta(hours=1)
        return token

    def reset_token_valido(self, token: str) -> bool:
        if not self.reset_token or not self.reset_token_expira:
            return False
        expira = self.reset_token_expira
        if expira.tzinfo is None:
            expira = expira.replace(tzinfo=timezone.utc)
        return self.reset_token == token and expira > datetime.now(timezone.utc)

    def limpar_reset_token(self) -> None:
        self.reset_token        = None
        self.reset_token_expira = None

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "nome":       self.nome,
            "email":      self.email,
            "perfil":     self.perfil,
            "ativo":      self.ativo,
            "bloqueado":  self.esta_bloqueado(),
            "criado_em":  self.criado_em.isoformat() if self.criado_em else None,
            "ultimo_acesso": self.ultimo_acesso.isoformat() if self.ultimo_acesso else None,
        }


class Parecer(db.Model):
    __tablename__ = "pareceres"

    id             = db.Column(db.Integer, primary_key=True)
    usuario_id     = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    numero_processo= db.Column(db.String(50))
    numero_req     = db.Column(db.String(50))
    num_parecer    = db.Column(db.String(50))
    requerente     = db.Column(db.String(200))
    municipio      = db.Column(db.String(100))
    conclusao      = db.Column(db.String(30))
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
    __tablename__ = "logs_acesso"

    id          = db.Column(db.Integer, primary_key=True)
    usuario_id  = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True)
    acao        = db.Column(db.String(50))
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
#  JWT
# ═══════════════════════════════════════════════════════════════════

def _gerar_token(usuario: Usuario) -> str:
    payload = {
        "sub":    str(usuario.id),
        "email":  usuario.email,
        "perfil": usuario.perfil,
        "exp":    datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRES_H),
        "iat":    datetime.now(timezone.utc),
        "jti":    secrets.token_hex(16),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _validar_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=["HS256"],
            options={"verify_exp": False}
        )
        exp = payload.get("exp", 0)
        agora = datetime.now(timezone.utc).timestamp()
        if agora - exp < 7200:
            log.info("Token expirado há %.0f min — aceito por tolerância", (agora - exp) / 60)
            return payload
        raise


def requer_login(f):
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

        g.usuario = usuario
        return f(*args, **kwargs)
    return wrapper


def requer_admin(f):
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

        if not re.match(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", email):
            return jsonify({"erro": "E-mail inválido."}), 400

        usuario = Usuario.query.filter_by(email=email).first()
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


def _enviar_email_reset(destinatario: str, nome: str, token: str) -> bool:
    if not BREVO_API_KEY or not EMAIL_REMETENTE:
        log.warning("Brevo não configurado — e-mail de reset não enviado.")
        return False
    try:
        link = f"{FRONTEND_URL}?reset_token={token}"

        html = f"""
<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#f9f9f9;padding:32px;border-radius:12px;">
  <div style="text-align:center;margin-bottom:24px;">
    <div style="font-size:36px;">🌿</div>
    <h2 style="color:#1a5c1e;margin:8px 0 4px;">NATURATINS</h2>
    <p style="color:#607d8b;font-size:13px;margin:0;">Sistema de Geração de Pareceres Técnicos</p>
  </div>
  <div style="background:white;border-radius:8px;padding:24px;border:1px solid #e0e0e0;">
    <p style="color:#37474f;font-size:15px;">Olá, <strong>{nome}</strong>!</p>
    <p style="color:#546e7a;font-size:14px;line-height:1.6;">
      Recebemos uma solicitação de recuperação de senha para sua conta.<br>
      Clique no botão abaixo para cadastrar uma nova senha.<br>
      <strong>O link é válido por 1 hora.</strong>
    </p>
    <div style="text-align:center;margin:28px 0;">
      <a href="{link}" style="background:#1a5c1e;color:white;padding:13px 32px;border-radius:7px;
         text-decoration:none;font-weight:700;font-size:15px;display:inline-block;">
        🔑 Redefinir minha senha
      </a>
    </div>
    <p style="color:#90a4ae;font-size:12px;text-align:center;">
      Se não foi você quem solicitou, ignore este e-mail.<br>
      Sua senha permanece a mesma.
    </p>
  </div>
  <p style="color:#b0bec5;font-size:11px;text-align:center;margin-top:16px;">
    NATURATINS — Instituto Natureza do Tocantins
  </p>
</div>"""

        texto = (f"Olá, {nome}!\n\nRecebemos uma solicitação de recuperação de senha.\n"
                 f"Acesse o link abaixo para criar uma nova senha (válido por 1 hora):\n{link}\n\n"
                 f"Se não foi você, ignore este e-mail.")

        payload = {
            "sender":     {"name": "NATURATINS", "email": EMAIL_REMETENTE},
            "to":         [{"email": destinatario, "name": nome}],
            "subject":    "Recuperação de senha — NATURATINS",
            "htmlContent": html,
            "textContent": texto,
        }

        r = req.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key":      BREVO_API_KEY,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=15,
        )
        r.raise_for_status()
        log.info("E-mail de reset enviado para %s (Brevo API)", destinatario)
        return True

    except Exception as exc:
        log.error("Falha ao enviar e-mail de reset: %s", exc)
        return False


@app.route("/auth/solicitar-reset", methods=["POST", "OPTIONS"])
@limiter.limit("5 per hour")
def solicitar_reset():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    dados = request.get_json(silent=True) or {}
    email = str(dados.get("email", "")).strip().lower()

    # Resposta genérica — não revela se e-mail existe
    RESP_OK = {"mensagem": "Se este e-mail estiver cadastrado, você receberá as instruções em breve."}

    if not email or not re.match(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", email):
        return jsonify(RESP_OK)

    usuario = Usuario.query.filter_by(email=email).first()
    if not usuario or not usuario.ativo:
        return jsonify(RESP_OK)

    token = usuario.gerar_reset_token()
    db.session.commit()

    _enviar_email_reset(usuario.email, usuario.nome, token)
    LogAcesso.registrar("reset_solicitado", f"email={email}", usuario.id)
    return jsonify(RESP_OK)


@app.route("/auth/redefinir-senha", methods=["POST", "OPTIONS"])
@limiter.limit("10 per hour")
def redefinir_senha():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    dados       = request.get_json(silent=True) or {}
    token       = str(dados.get("token", "")).strip()
    senha_nova  = str(dados.get("senha_nova", ""))

    if not token or not senha_nova:
        return jsonify({"erro": "Token e nova senha são obrigatórios."}), 400

    usuario = Usuario.query.filter_by(reset_token=token).first()
    if not usuario or not usuario.reset_token_valido(token):
        return jsonify({"erro": "Link inválido ou expirado. Solicite um novo."}), 400

    erros = _validar_forca_senha(senha_nova)
    if erros:
        return jsonify({"erro": erros}), 400

    usuario.definir_senha(senha_nova)
    usuario.limpar_reset_token()
    usuario.resetar_tentativas()
    db.session.commit()

    LogAcesso.registrar("senha_redefinida", f"email={usuario.email}", usuario.id)
    log.info("Senha redefinida via reset: %s", usuario.email)
    return jsonify({"mensagem": "Senha redefinida com sucesso! Você já pode fazer login."})


@app.route("/auth/validar-token-reset", methods=["POST", "OPTIONS"])
def validar_token_reset():
    """Verifica se um token de reset é válido antes de exibir o formulário."""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    dados = request.get_json(silent=True) or {}
    token = str(dados.get("token", "")).strip()

    if not token:
        return jsonify({"valido": False}), 400

    usuario = Usuario.query.filter_by(reset_token=token).first()
    if not usuario or not usuario.reset_token_valido(token):
        return jsonify({"valido": False, "erro": "Link inválido ou expirado."}), 400

    return jsonify({"valido": True, "nome": usuario.nome})


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


@app.route("/admin/usuarios/<int:uid>/desbloquear", methods=["POST"])
@requer_login
@requer_admin
def desbloquear_usuario(uid: int):
    usuario = db.session.get(Usuario, uid)
    if not usuario:
        return jsonify({"erro": "Usuário não encontrado."}), 404

    usuario.resetar_tentativas()
    db.session.commit()
    LogAcesso.registrar("usuario_desbloqueado", f"uid={uid}", g.usuario.id)
    log.info("Usuário %s desbloqueado por admin %s", usuario.email, g.usuario.email)
    return jsonify({"mensagem": "Conta desbloqueada com sucesso.", "usuario": usuario.to_dict()})


@app.route("/admin/logs", methods=["GET"])
@requer_login
@requer_admin
def listar_logs():
    pagina = request.args.get("pagina", 1, type=int)
    por_pagina = 50
    logs_q = (LogAcesso.query
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
        } for l in logs_q.items],
        "total":   logs_q.total,
        "paginas": logs_q.pages,
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
#  SIGAM — HELPERS via requests
# ═══════════════════════════════════════════════════════════════════

def _sigam_session() -> req.Session:
    """Cria sessão autenticada no SIGAM via requests."""
    s = req.Session()
    s.headers.update({"User-Agent": UA})

    cpf = SIGAM_USUARIO.replace(".", "").replace("-", "")
    cpf_fmt = f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}" if len(cpf) == 11 else SIGAM_USUARIO

    s.get(f"{SIGAM_BASE}/login.asp", timeout=30)
    r = s.post(f"{SIGAM_BASE}/login.asp", data={
        "txt_login": cpf_fmt,
        "txt_senha": SIGAM_SENHA,
        "acao": "entrar",
    }, allow_redirects=True, timeout=30)

    if "login.asp" in r.url:
        raise RuntimeError("Login no SIGAM falhou — verifique usuário/senha.")
    log.info("SIGAM login OK — URL: %s", r.url)
    return s


def _sigam_buscar_processo(s: req.Session, ano: str, orgao: str, sequencial: str) -> dict:
    """Busca processo no SIGAM e retorna cod_protocolo + numero_processo."""
    s.get(f"{SIGAM_BASE}/protocolo/pesquisa_simples.asp?area=processo", timeout=30)

    r = s.post(
        f"{SIGAM_BASE}/protocolo/impressao.asp",
        params={"area": "processo", "cod_impressao": "", "txt_funcao": ""},
        data={
            "txt_numero_ano": ano,
            "txt_numero_orgao": orgao,
            "txt_numero_sequencial": sequencial,
            "acao": "PESQUISAR",
        },
        timeout=30,
        allow_redirects=True,
    )

    m = re.search(r"cod_protocolo=(\d+)", r.url + r.text)
    if not m:
        raise RuntimeError(f"Processo {ano}/{orgao}/{sequencial} não encontrado no SIGAM.")

    cod_protocolo = m.group(1)

    # Extrai número do processo do HTML
    soup = BeautifulSoup(r.text, "html.parser")
    numero_processo = ""
    for td in soup.find_all("td"):
        txt = td.get_text(strip=True)
        m2 = re.match(r"(\d{4}/\d+/\d+)", txt)
        if m2:
            numero_processo = m2.group(1)
            break
    if not numero_processo:
        numero_processo = f"{ano}/{orgao}/{sequencial}"

    return {"cod_protocolo": cod_protocolo, "numero_processo": numero_processo}


def _sigam_coletar_docs(s: req.Session, cod_protocolo: str) -> list:
    """Coleta documentos juntados ao processo."""
    ACOES = ("alterar.asp", "assinar.asp", "cancelar.asp", "distribuir.asp",
             "movimentar.asp", "comentar.asp", "vincular.asp", "pendencia.asp",
             "responder.asp", "enquadramento.asp", "arquivar.asp")

    r = s.get(
        f"{SIGAM_BASE}/protocolo/impressao_processo.asp",
        params={"cod_protocolo": cod_protocolo, "area": "processo"},
        timeout=30,
    )
    soup = BeautifulSoup(r.text, "html.parser")
    candidatos, vistos = [], set()

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if not href.startswith("http"):
            href = SIGAM_BASE + "/" + href.lstrip("/")
        mc = re.search(r"cod_protocolo=(\d+)", href)
        if not mc:
            continue
        cp = mc.group(1)
        if cp == cod_protocolo or cp in vistos:
            continue
        if any(ac in href.lower() for ac in ACOES):
            continue
        vistos.add(cp)
        candidatos.append((a.get_text(strip=True), href, cp))

    return candidatos


def _sigam_extrair_rt(s: req.Session, cod: str, cod_protocolo: str, visitados: set, nivel: int = 0) -> dict:
    """Busca dados do RT em documentos juntados recursivamente."""
    if not cod or nivel > 3 or cod in visitados:
        return {}
    visitados.add(cod)

    ACOES = ("alterar.asp", "assinar.asp", "cancelar.asp", "distribuir.asp",
             "movimentar.asp", "comentar.asp", "vincular.asp", "pendencia.asp",
             "responder.asp", "enquadramento.asp", "arquivar.asp")

    for url in [
        f"{SIGAM_BASE}/protocolo/impressao.asp?cod_protocolo={cod}&area=documento",
        f"{SIGAM_BASE}/protocolo/impressao_processo.asp?cod_protocolo={cod}&area=processo",
    ]:
        r = s.get(url, timeout=30)
        texto = BeautifulSoup(r.text, "html.parser").get_text(separator="\n", strip=True)
        rt = _extrair_rt_do_texto(texto)
        if rt:
            return rt

        # Busca filhos
        soup = BeautifulSoup(r.text, "html.parser")
        filhos, vistos_f = [], set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            mc = re.search(r"cod_protocolo=(\d+)", href)
            if not mc:
                continue
            cf = mc.group(1)
            if cf in (cod, cod_protocolo) or cf in vistos_f:
                continue
            if any(ac in href.lower() for ac in ACOES):
                continue
            vistos_f.add(cf)
            filhos.append(cf)
        for cf in reversed(filhos):
            rt = _sigam_extrair_rt(s, cf, cod_protocolo, visitados, nivel + 1)
            if rt:
                return rt
    return {}


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


# ═══════════════════════════════════════════════════════════════════
#  SIGCAR — HELPERS via requests
# ═══════════════════════════════════════════════════════════════════

def _sigcar_session() -> req.Session:
    """Cria sessão autenticada no SIGCAR via requests."""
    s = req.Session()
    s.headers.update({"User-Agent": UA})
    s.get(SIGCAR_BASE, timeout=30)
    r = s.post(f"{SIGCAR_BASE}/login/login.jhtml", data={
        "j_username": SIGCAR_USUARIO,
        "j_password": SIGCAR_SENHA,
    }, allow_redirects=True, timeout=30)
    if "login" in r.url.lower() and "logout" not in r.url.lower():
        raise RuntimeError("Login no SIGCAR falhou — verifique usuário/senha.")
    log.info("SIGCAR login OK — URL: %s", r.url)
    return s


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


def _sigcar_buscar_imovel(s: req.Session, numero_car: str) -> dict:
    """Busca imóvel pelo número do CAR e retorna dados completos."""
    s.get(f"{SIGCAR_BASE}/imovel/consultar/inicio.jhtml", timeout=30)

    r = s.post(
        f"{SIGCAR_BASE}/imovel/consultar.jhtml",
        data={
            "gerarRelatorio": "false",
            "numeroPagina": "1",
            "registrosPorPagina": "10",
            "codigoCar": numero_car,
            "nomePropriedade": "",
            "nomeProprietario": "",
            "cpfCnpjProprietario": "",
            "codigoImovel": "",
            "siglaEstado": "Tocantins",
            "codigosTipoImovel": "todos",
            "codigosStatusPropriedade": ["ER","EA","IN","EM","AT","CO","RE","SU","CA","PE"],
            "codigosCondicaoPropriedade": "todos",
            "codigosStatusPra": "todos",
            "codigosStatusUsuario": "todos",
            "codigosOrgaoConveniado": "-1",
        },
        timeout=30,
    )

    soup = BeautifulSoup(r.text, "html.parser")

    # Pega primeira linha da tabela de resultados (status ATIVO preferencial)
    linhas = soup.select("table.listagem tbody tr")
    if not linhas:
        raise RuntimeError(f"CAR {numero_car} não encontrado no SIGCAR.")

    # Prefere linha ATIVO, senão pega a primeira
    linha = None
    for l in linhas:
        if "ATIVO" in l.get("class", []):
            linha = l
            break
    if not linha:
        linha = linhas[0]

    tds = linha.find_all("td")
    nome_imovel = tds[1].get_text(strip=True) if len(tds) > 1 else ""
    status_car  = tds[2].get_text(strip=True) if len(tds) > 2 else ""
    municipio   = tds[4].get_text(strip=True) if len(tds) > 4 else ""
    area_ha     = tds[5].get_text(strip=True) if len(tds) > 5 else ""
    mod_fiscais = tds[6].get_text(strip=True) if len(tds) > 6 else ""
    cadastrante = tds[7].get_text(strip=True) if len(tds) > 7 else ""
    data_cad    = tds[8].get_text(strip=True) if len(tds) > 8 else ""

    # Link da ficha
    link_ficha = ""
    a_ficha = linha.select_one("a[href*='ficha.jhtml']")
    if a_ficha:
        link_ficha = SIGCAR_BASE + a_ficha["href"] if not a_ficha["href"].startswith("http") else a_ficha["href"]

    # Acessa ficha detalhada se disponível
    dados_ficha = {}
    if link_ficha:
        dados_ficha = _sigcar_ficha(s, link_ficha)

    return {
        "nome_imovel":    nome_imovel,
        "status_car":     status_car,
        "municipio":      municipio,
        "area_ha":        _num(area_ha),
        "modulos_fiscais": _num(mod_fiscais),
        "cadastrante":    cadastrante,
        "data_cadastro":  data_cad,
        **dados_ficha,
    }


def _sigcar_ficha(s: req.Session, url_ficha: str) -> dict:
    """Acessa a ficha do imóvel e extrai dados via JSON embutido no JS."""
    import json as _json
    r = s.get(url_ficha, timeout=30)
    soup = BeautifulSoup(r.text, "html.parser")

    # Proprietário — tabela de domínio (pessoa física)
    nome_req = ""
    cpf_req  = ""
    tabela_pf = soup.find(id="tabela_ficha_pf")
    if tabela_pf:
        tbody = tabela_pf.find("tbody")
        trs = tbody.find_all("tr") if tbody else tabela_pf.find_all("tr")
        for tr in trs:
            tds = tr.find_all("td")
            if tds and tds[0].get_text(strip=True):
                nome_req = tds[0].get_text(strip=True)
                cpf_req  = tds[1].get_text(strip=True) if len(tds) > 1 else ""
                break

    # Dados de área — JSON embutido: atualizarCalculoAreas(JSON.parse('...'))
    areas = {}
    for script in soup.find_all("script"):
        txt = script.string or ""
        m = re.search(r"atualizarCalculoAreas\(JSON\.parse\('(\{.*?\})'\)\)", txt, re.DOTALL)
        if m:
            try:
                areas = _json.loads(m.group(1))
                log.info("SIGCAR: JSON de áreas extraído com %d campos", len(areas))
            except Exception as e:
                log.warning("SIGCAR: falha ao parsear JSON de áreas: %s", e)
            break

    def _av(key):
        v = areas.get(key)
        return _num(str(v)) if v is not None else 0.0

    def _ap(key):
        v = areas.get(key + "Porcentagem") or areas.get(key + "PorcentagemLiquida") or ""
        return str(v) if v else ""

    # Área total e módulos fiscais
    area_total_txt = ""
    mod_fiscais_txt = ""
    el_area = soup.find(id="detalheAreaImovel")
    if el_area:
        area_total_txt = el_area.get_text(strip=True)
    el_mod = soup.find(id="detalheNumeroModulosFiscais")
    if el_mod:
        mod_fiscais_txt = el_mod.get_text(strip=True)

    # Data de cadastro
    data_cadastro = ""
    td_data = soup.select_one("table.historico_propriedades_entidades tbody tr td._data")
    if td_data:
        data_cadastro = td_data.get_text(strip=True)[:10]

    return {
        "nome_requerente":         nome_req,
        "cpf_requerente":          cpf_req,
        "area_vetorizada":         _av("areaImovel"),
        "area_liquida":            _av("areaImovelLiquida"),
        "remanescente":            _av("vegetacaoNativa"),
        "consolidada":             _av("areaConsolidada"),
        "antropizada":             _av("areaAntropizadaApos22072008"),
        "uso_alternativo":         _av("areaUsoAlternativo"),
        "pousio":                  _av("areaPousio"),
        "infra_publica":           _av("areaInfraestruturaPublica"),
        "utilidade_publica":       _av("areaUtilidadePublica"),
        "servidao":                _av("areaServidaoAdministrativaTotal"),
        "app":                     _av("appGeral"),
        "app_61a":                 _av("appEscadinha"),
        "app_a_recuperar":         _av("appDegradada"),
        "reserva_legal":           _av("arlProposta"),
        "reserva_legal_pct":       _ap("arlProposta"),
        "suplementar":             _av("arlSuplementar"),
        "rl_a_recuperar":          _av("arlDegradada"),
        "reserva_legal_total":     _av("arlTotal"),
        "reserva_legal_total_pct": _ap("arlTotal"),
        "arl_com_vegetacao":       _av("arlComVegetacao"),
        "area_escriturada":        _num(area_total_txt),
        "data_sigcar":             data_cadastro,
    }


# ═══════════════════════════════════════════════════════════════════
#  ROTAS SIGCAR
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/buscar-car", methods=["POST", "OPTIONS"])
@limiter.limit("30 per hour")
def buscar_car():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

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

    try:
        numero_car = (request.json or {}).get("car", "")
        if not numero_car:
            return jsonify({"sucesso": False, "mensagem": "Número do CAR não informado."})

        LogAcesso.registrar("busca_car", f"car={numero_car}", usuario.id)
        log.info("CAR: %s — por %s", numero_car, usuario.email)

        s = _sigcar_session()
        dados = _sigcar_buscar_imovel(s, str(numero_car).strip())

        log.info("SIGCAR OK: car=%s municipio=%s", numero_car, dados.get("municipio"))
        return jsonify({"sucesso": True, **dados})

    except Exception as exc:
        log.error("CAR erro: %s", exc)
        return jsonify({"sucesso": False, "mensagem": str(exc)})


# ═══════════════════════════════════════════════════════════════════
#  ROTAS SIGAM
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/buscar-sigam", methods=["POST", "OPTIONS"])
def buscar_sigam():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"erro": "Token não fornecido."}), 401
    try:
        payload  = _validar_token(auth[7:])
        usuario  = db.session.get(Usuario, int(payload["sub"]))
        if not usuario or not usuario.ativo:
            return jsonify({"erro": "Usuário inativo."}), 403
    except jwt.InvalidTokenError as e:
        return jsonify({"erro": "Token inválido: " + str(e)}), 401

    try:
        dados      = request.json or {}
        ano        = str(dados.get("ano", "")).strip()
        orgao      = str(dados.get("orgao", "")).strip()
        sequencial = str(dados.get("sequencial", "")).strip()

        if not all([ano, orgao, sequencial]):
            return jsonify({"sucesso": False, "mensagem": "Informe Ano, Órgão e Sequencial."})

        LogAcesso.registrar("busca_sigam", f"{ano}/{orgao}/{sequencial}", usuario.id)
        log.info("SIGAM: %s/%s/%s — por %s", ano, orgao, sequencial, usuario.email)

        # ── Usa proxy local se configurado ──────────────────────────
        if SIGAM_PROXY_URL:
            log.info("SIGAM via proxy: %s", SIGAM_PROXY_URL)
            r = req.post(
                f"{SIGAM_PROXY_URL.rstrip('/')}/proxy/sigam",
                headers={"X-Proxy-Chave": SIGAM_PROXY_CHAVE,
                         "Content-Type": "application/json"},
                json={"ano": ano, "orgao": orgao, "sequencial": sequencial},
                timeout=120,
            )
            return jsonify(r.json())
        # ── Acesso direto (requer IP liberado no SIGAM) ──────────────

        s = _sigam_session()
        proc = _sigam_buscar_processo(s, ano, orgao, sequencial)
        cod_protocolo   = proc["cod_protocolo"]
        numero_processo = proc["numero_processo"]

        # Coleta documentos juntados
        docs = _sigam_coletar_docs(s, cod_protocolo)
        cp_ultimo = docs[-1][2] if docs else ""
        numero_requerimento = (docs[-1][0] or f"cod={cp_ultimo}") if docs else ""

        # Busca RT
        visitados: set = set()
        dados_rt = _sigam_extrair_rt(s, cp_ultimo, cod_protocolo, visitados) if cp_ultimo else {}

        # Tenta extrair nº do requerimento se não encontrado
        if not dados_rt.get("num_requerimento_doc") and docs:
            cp_primeiro = docs[0][2]
            r = s.get(
                f"{SIGAM_BASE}/protocolo/impressao.asp",
                params={"cod_protocolo": cp_primeiro, "area": "documento"},
                timeout=30,
            )
            txt = BeautifulSoup(r.text, "html.parser").get_text(separator="\n", strip=True)
            for padrao in [
                r"REQUERIMENTO\s+([\d][\d\-/]+[\d])",
                r"N[\u00ba\u00b0]\s*:?\s*([\d]+/\d{4})",
                r"IDENTIFICAÇÃO[:\s]+([\d][\d\-/]+[\d])",
                r"ORIGEM[:\s]+([\d]+/\d{4})",
            ]:
                m3 = re.search(padrao, txt, re.IGNORECASE)
                if m3:
                    dados_rt["num_requerimento_doc"] = m3.group(1).strip()
                    break

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


# ═══════════════════════════════════════════════════════════════════
#  HEALTHCHECK E SEGURANÇA
# ═══════════════════════════════════════════════════════════════════

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


@app.route("/init-db", methods=["GET"])
def init_db_manual():
    try:
        _inicializar_banco()
        return jsonify({"status": "ok", "mensagem": "Banco inicializado com sucesso."})
    except Exception as e:
        return jsonify({"status": "erro", "mensagem": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "naturatins-parecer"})


@app.after_request
def aplicar_headers_seguranca(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]            = "DENY"
    response.headers["X-XSS-Protection"]           = "1; mode=block"
    response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"]  = "max-age=31536000; includeSubDomains"
    response.headers.pop("Server", None)
    return response


# ═══════════════════════════════════════════════════════════════════
#  INICIALIZAÇÃO DO BANCO
# ═══════════════════════════════════════════════════════════════════

def _inicializar_banco():
    db.create_all()

    # Migração automática — adiciona colunas novas se ainda não existirem
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text("""
                ALTER TABLE usuarios
                ADD COLUMN IF NOT EXISTS reset_token VARCHAR(128),
                ADD COLUMN IF NOT EXISTS reset_token_expira TIMESTAMP;
            """))
            conn.commit()
        log.info("Migração de colunas reset_token concluída (ou já existiam).")
    except Exception as e:
        log.warning("Migração reset_token ignorada: %s", e)

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
#  LEITURA DE CERTIDÃO DE INTEIRO TEOR VIA GEMINI API
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/ler-certidao", methods=["POST", "OPTIONS"])
def ler_certidao():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    # Autenticação manual
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return jsonify({"erro": "Não autenticado."}), 401
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        usuario = db.session.get(Usuario, payload.get("sub"))
        if not usuario or not usuario.ativo:
            return jsonify({"erro": "Sessão inválida."}), 401
        g.usuario = usuario
    except Exception:
        return jsonify({"erro": "Token inválido."}), 401

    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    if not GEMINI_API_KEY:
        return jsonify({"erro": "GEMINI_API_KEY não configurada no Render."}), 503

    pdf_bytes = None
    if request.files.get("pdf"):
        pdf_bytes = request.files["pdf"].read()
    elif request.is_json:
        b64 = request.json.get("pdf_base64", "")
        if b64:
            try:
                pdf_bytes = base64.b64decode(b64)
            except Exception:
                return jsonify({"erro": "Base64 inválido."}), 400

    if not pdf_bytes:
        return jsonify({"erro": "Nenhum PDF enviado."}), 400
    if len(pdf_bytes) > 15 * 1024 * 1024:
        return jsonify({"erro": "PDF muito grande (máx. 15 MB)."}), 400

    pdf_b64 = base64.b64encode(pdf_bytes).decode()

    prompt = """Analise esta certidão de inteiro teor de imóvel rural e extraia APENAS as seguintes informações em JSON puro (sem markdown, sem backticks):
{
  "matriculas": "número(s) da matrícula separados por vírgula, ex: 1234 ou 1234, 5678",
  "area_ha": "área total em hectares como aparece no documento, ex: 178,4343 ha",
  "averbacao_reserva_legal": "Sim ou Não — se há averbação de reserva legal registrada no documento",
  "area_reserva_legal_averbada": "área da reserva legal averbada como aparece no documento. Se não houver averbação use string vazia"
}
Se algum dado não for encontrado use string vazia "". Responda APENAS com o JSON."""

    import json as _json, time as _time

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload_gemini = {
        "contents": [{"parts": [
            {"inline_data": {"mime_type": "application/pdf", "data": pdf_b64}},
            {"text": prompt}
        ]}],
        "generationConfig": {"maxOutputTokens": 512, "temperature": 0,
                             "thinkingConfig": {"thinkingBudget": 0}}
    }

    try:
        import json as _json

        r = req.post(url, headers={"Content-Type": "application/json"},
                     json=payload_gemini, timeout=30)

        if r.status_code == 429:
            log.warning("Gemini 429 — rate limit atingido")
            return jsonify({"erro": "RATE_LIMIT"}), 429

        r.raise_for_status()
        texto = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        dados = _json.loads(re.sub(r"```json|```", "", texto).strip())
        LogAcesso.registrar("certidao_lida", "ok", g.usuario.id)
        return jsonify({"sucesso": True, **dados})

    except Exception as exc:
        log.error("Erro ao ler certidão: %s", exc)
        return jsonify({"erro": f"Erro ao processar: {exc}"}), 500


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
