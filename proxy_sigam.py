"""
╔══════════════════════════════════════════════════════════════════╗
║           PROXY SIGAM — NATURATINS                               ║
║  Rode este script em qualquer computador dentro da rede          ║
║  do NATURATINS. Ele recebe requisições do Render e as            ║
║  repassa ao SIGAM, devolvendo os dados ao sistema.               ║
║                                                                  ║
║  Requisitos:  pip install flask requests beautifulsoup4          ║
║  Iniciar:     python proxy_sigam.py                              ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os, re, logging, io
from flask import Flask, request, jsonify
import requests as req
from bs4 import BeautifulSoup

# Extração de PDF
try:
    from pdfminer.high_level import extract_text as pdf_extract_text
    from pdfminer.layout import LAParams
    TEM_PDFMINER = True
except ImportError:
    TEM_PDFMINER = False
    log_temp = logging.getLogger("proxy-sigam")
    log_temp.warning("pdfminer não instalado — instale com: pip install pdfminer.six")

# ══════════════════════════════════════════════════════════════════
#  CONFIGURAÇÃO — edite aqui ou use variáveis de ambiente
# ══════════════════════════════════════════════════════════════════

SIGAM_USUARIO  = os.environ.get("SIGAM_USUARIO",  "")   # CPF sem pontos
SIGAM_SENHA    = os.environ.get("SIGAM_SENHA",    "")
SIGAM_BASE     = "https://sigam.to.gov.br/proton"

# Chave secreta — deve ser a mesma definida em PROXY_CHAVE no Render
PROXY_CHAVE    = os.environ.get("PROXY_CHAVE", "naturatins-proxy-2026")

# Porta local do proxy
PORTA          = int(os.environ.get("PROXY_PORTA", "5050"))

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"

# ══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy-sigam")

app = Flask(__name__)


# ══════════════════════════════════════════════════════════════════
#  HELPERS SIGAM (idênticos ao app.py do Render)
# ══════════════════════════════════════════════════════════════════

def _sigam_session() -> req.Session:
    s = req.Session()
    s.headers.update({"User-Agent": UA})
    cpf = SIGAM_USUARIO.replace(".", "").replace("-", "")
    cpf_fmt = f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}" if len(cpf) == 11 else SIGAM_USUARIO

    r_login_page = s.get(f"{SIGAM_BASE}/login.asp", timeout=60)
    log.info("GET login.asp -> status=%s url_final=%s tamanho=%d",
             r_login_page.status_code, r_login_page.url, len(r_login_page.text))

    # Monta o payload a partir do formulário real da página (captura também
    # qualquer campo oculto/token que o SIGAM exija além de usuário e senha).
    soup_login = BeautifulSoup(r_login_page.text, "html.parser")
    form = soup_login.find("form")
    payload = {}
    campos_encontrados = []
    if form:
        for inp in form.find_all(["input", "select"]):
            nome = inp.get("name")
            if not nome:
                continue
            payload[nome] = inp.get("value", "")
            campos_encontrados.append(nome)
    log.info("Campos encontrados no formulário de login: %s", campos_encontrados)

    # Garante os campos de usuário/senha corretos, tentando os nomes mais
    # prováveis (ajusta automaticamente se o formulário usar outro nome).
    campo_login = next((c for c in campos_encontrados if "login" in c.lower() or "usuario" in c.lower() or "cpf" in c.lower()), "txt_login")
    campo_senha = next((c for c in campos_encontrados if "senha" in c.lower() or "password" in c.lower() or "pass" in c.lower()), "txt_senha")
    payload[campo_login] = cpf_fmt
    payload[campo_senha] = SIGAM_SENHA
    payload.setdefault("acao", "entrar")

    log.info("POST login.asp usando campo_login=%r campo_senha=%r (payload keys=%s)",
              campo_login, campo_senha, list(payload.keys()))

    r = s.post(f"{SIGAM_BASE}/login.asp", data=payload, allow_redirects=True, timeout=60)
    log.info("POST login.asp -> status=%s url_final=%s", r.status_code, r.url)

    if "login.asp" in r.url:
        # Diagnóstico completo antes de falhar, para não precisar repetir o teste
        trecho = r.text[:1500].replace("\n", " ").replace("\r", "")
        log.error("Login falhou. Trecho da resposta: %s", trecho)
        raise RuntimeError("Login no SIGAM falhou — verifique usuário/senha.")
    log.info("SIGAM login OK")
    return s


def _sigam_buscar_processo(s, ano, orgao, sequencial):
    s.get(f"{SIGAM_BASE}/protocolo/pesquisa_simples.asp?area=processo", timeout=60)
    r = s.post(
        f"{SIGAM_BASE}/protocolo/impressao.asp",
        params={"area": "processo", "cod_impressao": "", "txt_funcao": ""},
        data={
            "txt_numero_ano":        ano,
            "txt_numero_orgao":      orgao,
            "txt_numero_sequencial": sequencial,
            "acao": "PESQUISAR",
        },
        timeout=60, allow_redirects=True,
    )
    m = re.search(r"cod_protocolo=(\d+)", r.url + r.text)
    if not m:
        raise RuntimeError(f"Processo {ano}/{orgao}/{sequencial} não encontrado no SIGAM.")
    cod_protocolo = m.group(1)
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


def _sigam_get_cod_usuario_orgao(s, cod_protocolo) -> tuple:
    """Extrai cod_usuario e cod_orgao da página principal do processo."""
    r = s.get(
        f"{SIGAM_BASE}/protocolo/impressao_processo.asp",
        params={"cod_protocolo": cod_protocolo, "area": "processo"},
        timeout=60,
    )
    # Busca cod_usuario e cod_orgao no HTML/JS da página
    m_usuario = re.search(r"cod_usuario[='\"\s:]+(\d+)", r.text)
    m_orgao   = re.search(r"cod_orgao[='\"\s:]+(\d+)", r.text)
    cod_usuario = m_usuario.group(1) if m_usuario else "14251"
    cod_orgao   = m_orgao.group(1)   if m_orgao   else "1100"
    log.info("cod_usuario=%s cod_orgao=%s", cod_usuario, cod_orgao)
    return cod_usuario, cod_orgao


def _sigam_coletar_docs(s, cod_protocolo):
    """Busca documentos juntados via endpoint AJAX protocolo_juntado.aspx."""
    cod_usuario, cod_orgao = _sigam_get_cod_usuario_orgao(s, cod_protocolo)

    r = s.get(
        f"{SIGAM_BASE}/x64/impressao/protocolo_juntado.aspx",
        params={
            "cod_protocolo": cod_protocolo,
            "cod_usuario":   cod_usuario,
            "cod_orgao":     cod_orgao,
            "txt_area":      "processo",
        },
        timeout=60,
    )
    log.info("protocolo_juntado.aspx status=%d tamanho=%d", r.status_code, len(r.text))

    soup = BeautifulSoup(r.text, "html.parser")
    candidatos, vistos = [], set()

    for tr in soup.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 2:
            continue
        # Primeira coluna: número do documento (link)
        a = tds[0].find("a", href=True)
        if not a:
            continue
        mc = re.search(r"cod_protocolo=(\d+)", a["href"])
        if not mc:
            # Tenta via onclick
            onclick_tag = tds[0].find(onclick=True)
            if onclick_tag:
                mo = re.search(r"fn_exibir_arquivo\((\d+)", onclick_tag.get("onclick",""))
                if mo:
                    mc_cp = mo.group(1)
                else:
                    continue
            else:
                continue
        else:
            mc_cp = mc.group(1)

        if mc_cp == cod_protocolo or mc_cp in vistos:
            continue
        vistos.add(mc_cp)

        numero_doc = a.get_text(strip=True)
        # Segunda coluna: tipo documental
        tipo_doc = tds[1].get_text(strip=True) if len(tds) > 1 else ""
        texto_completo = f"{numero_doc} {tipo_doc}".strip()

        url_completa = f"{SIGAM_BASE}/protocolo/impressao_processo.asp?cod_protocolo={mc_cp}&area=processo"
        candidatos.append((texto_completo, url_completa, mc_cp))
        log.info("Doc: cp=%s numero=%s tipo=%s", mc_cp, numero_doc, tipo_doc[:30])

    return candidatos


def _extrair_rt_do_texto(body_text):
    if not body_text:
        return {}
    RT_MARCADORES = (
        "RESPONSÁVEL TÉCNICO", "RESPONSAVEL TECNICO",
        "IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO",
        "DADOS DO RESPONSÁVEL TÉCNICO",
        "IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO",
        "Nome/Razão social:",
    )
    texto_upper = body_text.upper()
    if not any(m.upper() in texto_upper for m in RT_MARCADORES):
        return {}

    def _linha_apos(marcadores_lista, texto):
        for marc in marcadores_lista:
            idx = texto.upper().find(marc.upper())
            if idx == -1:
                continue
            trecho = texto[idx + len(marc):]
            for linha in trecho.splitlines():
                v = linha.strip().strip(":").strip()
                if v and v.upper() not in (marc.upper(), "") and len(v) > 1:
                    return v
        return ""

    result = {}

    # ── Nome: linha imediatamente após "RESPONSÁVEL TÉCNICO:" ────
    for marc_nome in ["RESPONSÁVEL TÉCNICO:", "RESPONSAVEL TECNICO:",
                      "IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO",
                      "Nome/Razão social:"]:
        idx = body_text.upper().find(marc_nome.upper())
        if idx == -1:
            continue
        trecho = body_text[idx + len(marc_nome):]
        for linha in trecho.splitlines():
            v = linha.strip().strip(":")
            # Nome deve ter pelo menos duas palavras e não ser um marcador
            if (v and len(v) > 5 and " " in v
                    and not any(x in v.upper() for x in
                                ["E-MAIL", "CPF", "TELEFONE", "CELULAR",
                                 "TÍTULO", "ART", "FONE", "HABILITAÇÃO"])):
                result["rt_nome"] = v
                break
        if result.get("rt_nome"):
            break

    # ── Demais campos ────────────────────────────────────────────
    for campo, marcadores in [
        ("rt_cpf",      ["CPF/CNPJ:", "CPF:", "C.P.F.:", "C.P.F:/C.N.P.J.:"]),
        ("rt_titulo",   ["TÍTULO PROFISSIONAL:", "Título Profissional:",
                         "TITULO PROFISSIONAL:", "HABILITAÇÃO:", "Nome do Representante legal:"]),
        ("rt_art",      ["ART Nº:", "ART:", "Nº ART:", "N° ART:", "Nº DA ART:",
                         "NÚMERO ART:", "ART N°:", "ART No:"]),
        ("rt_email",    ["E-MAIL:", "Email:", "E-mail:", "EMAIL:"]),
        ("rt_telefone", ["TELEFONE:", "Telefone:", "CELULAR:", "Fone:", "TEL.:", "FONE:"]),
    ]:
        # Busca apenas no trecho após "RESPONSÁVEL TÉCNICO"
        idx_rt = body_text.upper().find("RESPONSÁVEL TÉCNICO")
        if idx_rt == -1:
            idx_rt = body_text.upper().find("RESPONSAVEL TECNICO")
        trecho = body_text[idx_rt:] if idx_rt != -1 else body_text
        v = _linha_apos(marcadores, trecho)
        if v:
            result[campo] = v

    # ── Número do requerimento ───────────────────────────────────
    for padrao in [
        r"REQUERIMENTO\s+N[°oº]?\s*:?\s*([\d][\d\-/]+[\d])",
        r"REQUERIMENTO\s+([\d][\d\-/]+[\d])",
        r"N[ºo°]\s*:?\s*([\d]+/\d{4})",
        r"ORIGEM[:\s]+([\d]+/\d{4})",
        r"PROCESSO\s+N[°oº]?\s*:?\s*(\d{4}/\d+/\d+)",
    ]:
        m = re.search(padrao, body_text, re.IGNORECASE)
        if m:
            result["num_requerimento_doc"] = m.group(1).strip()
            break

    return result


def _extrair_texto_pdf(conteudo_bytes: bytes) -> str:
    """Extrai texto de um PDF em memória usando pdfminer."""
    if not TEM_PDFMINER:
        return ""
    try:
        texto = pdf_extract_text(
            io.BytesIO(conteudo_bytes),
            laparams=LAParams(line_margin=0.5),
        )
        return texto or ""
    except Exception as e:
        log.warning("Falha ao extrair PDF: %s", e)
        return ""


def _extrair_cpf_interessado(html_text: str) -> str:
    """Busca CPF/CNPJ do proprietário/interessado via atributo title de <span>,
    padrão: title="CPF: 038.044.131-45\nRESPONSÁVEL: \nE-MAIL: ...".
    Não depende de posição/índice de tabela — só do texto do atributo title."""
    m = re.search(r'title="[^"]*CPF:\s*([\d./\-]+)', html_text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return ""


def _sigam_extrair_rt(s, cod, cod_protocolo, visitados, nivel=0, achados=None):
    ACOES = ("alterar.asp","assinar.asp","cancelar.asp","distribuir.asp",
             "movimentar.asp","comentar.asp","vincular.asp","pendencia.asp",
             "responder.asp","enquadramento.asp","arquivar.asp")
    if not cod or nivel > 3 or cod in visitados:
        return {}
    visitados.add(cod)
    if achados is None:
        achados = {}

    for url in [
        f"{SIGAM_BASE}/protocolo/impressao.asp?cod_protocolo={cod}&area=documento",
        f"{SIGAM_BASE}/protocolo/impressao_processo.asp?cod_protocolo={cod}&area=processo",
    ]:
        r = s.get(url, timeout=60)
        content_type = r.headers.get("Content-Type", "")
        log.info("cod=%s url=%s status=%s tipo=%s tamanho=%d primeiros4=%s",
                 cod, url.split("?")[0].split("/")[-1],
                 r.status_code, content_type[:40],
                 len(r.content), r.content[:4])

        if not achados.get("cpf_requerente_sigam"):
            cpf_interessado = _extrair_cpf_interessado(r.text)
            if cpf_interessado:
                achados["cpf_requerente_sigam"] = cpf_interessado
                log.info("CPF do interessado encontrado em cod=%s: %s", cod, cpf_interessado)

        # ── PDF direto ───────────────────────────────────────────
        if "pdf" in content_type.lower() or r.content[:4] == b"%PDF":
            log.info("PDF encontrado em cod=%s — extraindo texto...", cod)
            texto_pdf = _extrair_texto_pdf(r.content)
            log.info("PDF texto (%d chars): %.200s", len(texto_pdf), texto_pdf.replace('\n',' '))
            rt = _extrair_rt_do_texto(texto_pdf)
            if rt:
                log.info("RT encontrado no PDF: %s", rt)
                return rt
            continue

        # ── Tenta baixar PDF via fn_exibir_arquivo ───────────────
        pdf_url = f"{SIGAM_BASE}/x64/impressao/protocolo_arquivo_download.aspx?cod_protocolo={cod}&txt_area=documento"
        try:
            rp = s.get(pdf_url, timeout=60)
            if rp.content[:4] == b"%PDF":
                log.info("PDF via download endpoint cod=%s", cod)
                texto_pdf = _extrair_texto_pdf(rp.content)
                log.info("PDF texto (%d chars): %.200s", len(texto_pdf), texto_pdf.replace('\n',' '))
                rt = _extrair_rt_do_texto(texto_pdf)
                if rt:
                    log.info("RT encontrado via download: %s", rt)
                    return rt
        except Exception as e:
            log.warning("Erro download PDF cod=%s: %s", cod, e)

        # ── HTML — tenta extrair do texto da página ──────────────
        texto = BeautifulSoup(r.text, "html.parser").get_text(separator="\n", strip=True)
        # Log do trecho ao redor do RT
        idx = texto.upper().find("RESPONSÁVEL TÉCNICO")
        if idx == -1:
            idx = texto.upper().find("RESPONSAVEL TECNICO")
        if idx != -1:
            log.info("Trecho RT (HTML):\n%s", texto[max(0,idx-50):idx+600])
        rt = _extrair_rt_do_texto(texto)
        if rt:
            log.info("RT encontrado no HTML cod=%s", cod)
            return rt

        # ── Procura links para PDFs ou subprocessos ──────────────
        soup = BeautifulSoup(r.text, "html.parser")
        filhos, vistos_f = [], set()

        for a in soup.find_all("a", href=True):
            href = a["href"]
            if not href.startswith("http"):
                href = SIGAM_BASE + "/" + href.lstrip("/")

            # Link direto para PDF
            if href.lower().endswith(".pdf") or "download" in href.lower() or "arquivo" in href.lower():
                try:
                    rp = s.get(href, timeout=60)
                    if rp.content[:4] == b"%PDF":
                        log.info("PDF via link direto: %s", href)
                        texto_pdf = _extrair_texto_pdf(rp.content)
                        rt = _extrair_rt_do_texto(texto_pdf)
                        if rt:
                            log.info("RT encontrado em PDF direto: %s", rt)
                            return rt
                except Exception as e:
                    log.warning("Erro ao baixar PDF %s: %s", href, e)
                continue

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
            rt = _sigam_extrair_rt(s, cf, cod_protocolo, visitados, nivel + 1, achados)
            if rt:
                return rt

    return {}


# ══════════════════════════════════════════════════════════════════
#  ROTAS DO PROXY
# ══════════════════════════════════════════════════════════════════

@app.route("/proxy/sigam", methods=["POST"])
def proxy_sigam():
    """Recebe requisição do Render e consulta o SIGAM localmente."""

    # Valida chave de segurança
    chave = request.headers.get("X-Proxy-Chave", "")
    if chave != PROXY_CHAVE:
        log.warning("Tentativa com chave inválida: %s", chave)
        return jsonify({"sucesso": False, "mensagem": "Chave inválida."}), 403

    dados      = request.json or {}
    ano        = str(dados.get("ano", "")).strip()
    orgao      = str(dados.get("orgao", "")).strip()
    sequencial = str(dados.get("sequencial", "")).strip()

    if not all([ano, orgao, sequencial]):
        return jsonify({"sucesso": False, "mensagem": "Informe ano, orgao e sequencial."})

    log.info("Consulta SIGAM: %s/%s/%s", ano, orgao, sequencial)

    try:
        s    = _sigam_session()
        proc = _sigam_buscar_processo(s, ano, orgao, sequencial)
        cod_protocolo   = proc["cod_protocolo"]
        numero_processo = proc["numero_processo"]

        docs       = _sigam_coletar_docs(s, cod_protocolo)
        log.info("Documentos encontrados: %d — %s", len(docs),
                 [(d[0][:30], d[2]) for d in docs])
        numero_req = docs[0][0] if docs else ""

        # Separa documentos de processos apensados (40311 = processo, 40319/40320 = doc)
        documentos    = [(t, u, cp) for t, u, cp in docs if "/40311/" not in t]
        apensados     = [(t, u, cp) for t, u, cp in docs if "/40311/" in t]

        log.info("Documentos: %d | Processos apensados: %d", len(documentos), len(apensados))

        # Para processos apensados, busca os documentos juntados dentro deles
        docs_apensados = []
        for texto, url, cp in reversed(apensados):
            log.info("Buscando docs dentro do processo apensado cp=%s texto=%s", cp, texto)
            sub_docs = _sigam_coletar_docs(s, cp)
            log.info("  → %d docs encontrados no apensado", len(sub_docs))
            docs_apensados.extend(sub_docs)

        # Junta todos: primeiro docs do processo principal, depois os do apensado (mais recentes)
        todos_docs = documentos + docs_apensados

        # Filtra requerimentos de todos
        requerimentos = [(t, u, cp) for t, u, cp in todos_docs if "REQUERIMENTO" in t.upper()]
        log.info("Total requerimentos (apensados + principal): %d", len(requerimentos))

        # Busca RT no ÚLTIMO requerimento (mais recente)
        visitados = set()
        dados_rt  = {}
        achados_interessado = {}

        if requerimentos:
            for texto, url, cp in reversed(requerimentos):
                log.info("Tentando RT no REQUERIMENTO cp=%s texto=%s", cp, texto)
                dados_rt = _sigam_extrair_rt(s, cp, cod_protocolo, visitados, achados=achados_interessado)
                if dados_rt:
                    break

        # Se não achou RT nos requerimentos, tenta todos os outros docs
        if not dados_rt:
            log.info("RT não encontrado nos requerimentos — varrendo demais docs")
            for texto, url, cp in reversed(todos_docs):
                if cp not in visitados:
                    log.info("Tentando RT em doc cp=%s texto=%s", cp, texto[:30])
                    dados_rt = _sigam_extrair_rt(s, cp, cod_protocolo, visitados, achados=achados_interessado)
                    if dados_rt:
                        break

        if not dados_rt.get("num_requerimento_doc") and docs:
            cp_primeiro = docs[0][2]
            r = s.get(
                f"{SIGAM_BASE}/protocolo/impressao.asp",
                params={"cod_protocolo": cp_primeiro, "area": "documento"},
                timeout=60,
            )
            txt = BeautifulSoup(r.text, "html.parser").get_text(separator="\n", strip=True)
            for padrao in [r"REQUERIMENTO\s+([\d][\d\-/]+[\d])",
                           r"N[ºo]\s*:?\s*([\d]+/\d{4})",
                           r"ORIGEM[:\s]+([\d]+/\d{4})"]:
                m3 = re.search(padrao, txt, re.IGNORECASE)
                if m3:
                    dados_rt["num_requerimento_doc"] = m3.group(1).strip()
                    break

        log.info("SIGAM OK: proc=%s RT=%s | CPF interessado=%s",
                 numero_processo, dados_rt, achados_interessado.get("cpf_requerente_sigam", ""))
        return jsonify({
            "sucesso":             True,
            "numero_processo":     numero_processo,
            "numero_requerimento": numero_req,
            "num_requerimento_doc":   dados_rt.get("num_requerimento_doc", ""),
            "resp_tecnico_nome":      dados_rt.get("rt_nome", ""),
            "resp_tecnico_cpf":       dados_rt.get("rt_cpf", ""),
            "resp_tecnico_email":     dados_rt.get("rt_email", ""),
            "resp_tecnico_tel":       dados_rt.get("rt_telefone", ""),
            "resp_tecnico_formacao":  dados_rt.get("rt_titulo", ""),
            "resp_tecnico_registro":  dados_rt.get("rt_art", ""),
            "cpf_requerente_sigam":   achados_interessado.get("cpf_requerente_sigam", ""),
        })

    except Exception as exc:
        log.error("Erro SIGAM: %s", exc)
        return jsonify({"sucesso": False, "mensagem": str(exc)})


@app.route("/proxy/ping", methods=["GET"])
def ping():
    """Verifica se o proxy está online."""
    return jsonify({"status": "online", "servico": "proxy-sigam-naturatins"})


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if not SIGAM_USUARIO or not SIGAM_SENHA:
        print("=" * 60)
        print("ATENÇÃO: Configure as variáveis antes de iniciar:")
        print("  set SIGAM_USUARIO=seucpfsempontos")
        print("  set SIGAM_SENHA=suasenha")
        print("  set PROXY_CHAVE=naturatins-proxy-2026")
        print("=" * 60)
    print(f"\n🟢 Proxy SIGAM rodando em http://0.0.0.0:{PORTA}")
    print(f"   Chave ativa: {PROXY_CHAVE}")
    print(f"   Teste: http://localhost:{PORTA}/proxy/ping\n")
    app.run(host="0.0.0.0", port=PORTA, debug=False)
