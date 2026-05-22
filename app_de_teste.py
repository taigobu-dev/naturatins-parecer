from flask import Flask, request, jsonify
from flask_cors import CORS
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import time
import re

app = Flask(__name__)
CORS(app)

# ==========================================
#           ROTA PARA O CAR
# ==========================================
@app.route('/api/buscar-car', methods=['POST', 'OPTIONS'])
def buscar_car():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    driver = None
    try:
        dados = request.json
        numero_car = dados.get('car')

        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-gpu')
        options.add_argument('--log-level=3')

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        wait = WebDriverWait(driver, 20)

        def limpar_num(texto):
            if not texto or str(texto).strip() in ['-', '']:
                return 0.0
            try:
                t = re.sub(r'<[^>]+>', '', str(texto)).strip()
                t = t.lower().replace('ha', '').strip()
                t = re.sub(r'\(.*?\)', '', t).strip()
                t = t.replace('.', '').replace(',', '.')
                return float(t) if t else 0.0
            except:
                return 0.0

        def buscar_td2(id_el, timeout=6):
            return buscar_xpath('//*[@id="' + id_el + '"]/td[2]', timeout)

        def buscar_xpath(xpath, timeout=6):
            try:
                el = WebDriverWait(driver, timeout).until(
                    EC.presence_of_element_located((By.XPATH, xpath))
                )
                txt = el.text.strip()
                if not txt:
                    txt = el.get_attribute("value") or ""
                if not txt:
                    txt = el.get_attribute("innerHTML") or ""
                return re.sub(r'<[^>]+>', '', str(txt)).strip()
            except:
                return ""

        def extrair_pct(texto):
            m = re.search(r'([\d,]+)\s*%', texto)
            return (m.group(1).replace(',', '.') + '%') if m else ''

        # ── LOGIN SIGCAR ──────────────────────────────────────────────
        driver.get("http://sigcar.semarh.to.gov.br/")
        wait.until(EC.presence_of_element_located((By.ID, "email"))).send_keys("taigo.auerswald@naturatins.to.gov.br")
        driver.find_element(By.ID, "senha").send_keys("Catarina050125")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(2)

        # ── BUSCA DO CAR ──────────────────────────────────────────────
        driver.get("http://sigcar.semarh.to.gov.br/imovel/consultar/inicio.jhtml")
        wait.until(EC.presence_of_element_located((By.ID, "codigoCar"))).send_keys(numero_car)
        driver.find_element(By.ID, "buscarButton").click()
        time.sleep(3)

        status_car_capturado = buscar_xpath('//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[3]/b')
        municipio_valor      = buscar_xpath('//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[5]')
        nome_imovel_valor    = buscar_xpath('//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[2]')

        wait.until(EC.element_to_be_clickable(
            (By.XPATH, '//*[@id="resultadoBusca"]/section/table/tbody/tr[1]/td[1]')
        )).click()
        time.sleep(4)

        # ── ABA: DADOS DO IMÓVEL ──────────────────────────────────────
        btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[1]/ul/li[1]/a')
        ))
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(3)

        area_escriturada_valor = limpar_num(buscar_xpath(
            '//*[@id="MAIN"]/section/div[1]/article/div[3]/article/section[4]/div/section/div/strong'
        ))

        # ── ABA: HISTÓRICO ────────────────────────────────────────────
        btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[1]/ul/li[3]/a')
        ))
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(3)

        data_sigcar_valor = buscar_xpath(
            '//*[@id="MAIN"]/section/div[1]/article/section[3]/section[2]/table[1]/tbody/tr[1]/td[2]'
        )

        # ── ABA: DOMÍNIO ──────────────────────────────────────────────
        btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[2]/ul/li[3]/a')
        ))
        driver.execute_script("arguments[0].click();", btn)
        try:
            wait.until(EC.presence_of_element_located((By.XPATH, '//*[@id="tabela_ficha_pf"]')))
            time.sleep(2)
        except:
            pass

        nome_requerente = buscar_xpath('//*[@id="tabela_ficha_pf"]/tbody/tr[1]/td[1]/div')
        cpf_requerente  = buscar_xpath('//*[@id="tabela_ficha_pf"]/tbody/tr[1]/td[2]')

        # ── ABA: VETOR ────────────────────────────────────────────────
        btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, '//*[@id="MAIN"]/section/div[1]/article/div[2]/nav[1]/ul/li[5]/a')
        ))
        driver.execute_script("arguments[0].click();", btn)
        time.sleep(6)

        area_vetorizada_valor = limpar_num(buscar_td2('areaImovel', timeout=10))
        area_liquida_valor    = limpar_num(buscar_td2('areaImovelLiquida', timeout=10))
        remanescente_val      = limpar_num(buscar_td2('vegetacaoNativa'))
        consolidada_val       = limpar_num(buscar_td2('areaConsolidada'))
        antropizada_val       = limpar_num(buscar_td2('areaAntropizadaApos22072008'))
        uso_alternativo_val   = limpar_num(buscar_td2('areaUsoAlternativo'))
        pousio_val            = limpar_num(buscar_td2('areaPousio'))
        infra_publica_val     = limpar_num(buscar_td2('areaInfraPublica'))
        utilidade_publica_val = limpar_num(buscar_td2('areaUtilidadePublica'))
        servidao_val          = limpar_num(buscar_td2('areaServidaoAdm'))
        app_val               = limpar_num(buscar_td2('appGeral'))
        app_61a_val           = limpar_num(buscar_td2('appEscadinha'))
        app_recuperar_val     = limpar_num(buscar_td2('appDegradada'))
        suplementar_val       = limpar_num(buscar_td2('arlSuplementar'))
        rl_recuperar_val      = limpar_num(buscar_td2('arlDegradada'))
        rl_total_val          = limpar_num(buscar_td2('arlTotal'))
        arl_veg_val           = limpar_num(buscar_td2('arlComVegetacao'))

        rl_val       = limpar_num(buscar_td2('arlProposta'))
        rl_pct       = extrair_pct(buscar_xpath('//*[@id="arlProposta"]'))
        rl_total_pct = extrair_pct(buscar_xpath('//*[@id="arlTotal"]'))

        return jsonify({
            'sucesso':                 True,
            'nome_requerente':         nome_requerente,
            'cpf_requerente':          cpf_requerente,
            'status_car':              status_car_capturado,
            'municipio':               municipio_valor,
            'denominacao_imovel':      nome_imovel_valor,
            'data_sigcar':             data_sigcar_valor,
            'area_escriturada':        area_escriturada_valor,
            'area_vetorizada':         area_vetorizada_valor,
            'area_liquida':            area_liquida_valor,
            'remanescente':            remanescente_val,
            'consolidada':             consolidada_val,
            'antropizada':             antropizada_val,
            'uso_alternativo':         uso_alternativo_val,
            'pousio':                  pousio_val,
            'infra_publica':           infra_publica_val,
            'utilidade_publica':       utilidade_publica_val,
            'servidao':                servidao_val,
            'app':                     app_val,
            'app_61a':                 app_61a_val,
            'app_a_recuperar':         app_recuperar_val,
            'reserva_legal':           rl_val,
            'reserva_legal_pct':       rl_pct,
            'suplementar':             suplementar_val,
            'rl_a_recuperar':          rl_recuperar_val,
            'reserva_legal_total':     rl_total_val,
            'reserva_legal_total_pct': rl_total_pct,
            'arl_com_vegetacao':       arl_veg_val,
        })

    except Exception as e:
        return jsonify({'sucesso': False, 'mensagem': str(e)})
    finally:
        if driver:
            driver.quit()


# ==========================================
#    EXTRAÇÃO DO TEXTO (com suporte a iframe)
# ==========================================
def _get_page_text(driver):
    """
    Retorna o texto da página, verificando frames e iframes.
    Aceita qualquer página que contenha dados de RT ou Requerente —
    não exige mais o marcador antigo 'IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO'.
    """
    # Marcadores que indicam que a página tem dados úteis
    MARCADORES = [
        'RESPONSÁVEL TÉCNICO:',
        'RESPONSAVEL TECNICO:',
        'IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO',
    ]

    def tem_dados(txt):
        return any(m in txt for m in MARCADORES)

    # 1) Texto da página principal
    try:
        text = driver.find_element(By.TAG_NAME, 'body').text
    except:
        text = ''

    if tem_dados(text):
        print("  -> Dados RT encontrados na página principal (" + str(len(text)) + " chars)")
        return text

    # 2) Tenta <frame> (frameset legado do SIGAM)
    frames = driver.find_elements(By.TAG_NAME, 'frame')
    for i, fr in enumerate(frames):
        try:
            driver.switch_to.frame(fr)
            ft = driver.find_element(By.TAG_NAME, 'body').text
            driver.switch_to.default_content()
            if tem_dados(ft):
                print("  -> Dados RT encontrados no frame[" + str(i) + "] (" + str(len(ft)) + " chars)")
                return ft
        except:
            try: driver.switch_to.default_content()
            except: pass

    # 3) Tenta <iframe>
    iframes = driver.find_elements(By.TAG_NAME, 'iframe')
    for i, fr in enumerate(iframes):
        try:
            driver.switch_to.frame(fr)
            ft = driver.find_element(By.TAG_NAME, 'body').text
            driver.switch_to.default_content()
            if tem_dados(ft):
                print("  -> Dados RT encontrados no iframe[" + str(i) + "] (" + str(len(ft)) + " chars)")
                return ft
        except:
            try: driver.switch_to.default_content()
            except: pass

    # 4) Nenhum marcador encontrado — salva debug completo e retorna o que tiver

    # Retorna o texto principal mesmo sem marcadores — _extrair_resp_tecnico tentará parsear
    return text


# ==========================================
#    EXTRAÇÃO DOS DADOS DO RT
# ==========================================
def _extrair_rt_do_texto(body_text):
    """
    Extrai RT e Requerente de um texto bruto (sem precisar do driver).
    Suporta ambos os formatos do SIGAM (novo e antigo).
    """
    if not body_text:
        return {}

    MARCADORES_RT = ['RESPONSÁVEL TÉCNICO', 'RESPONSAVEL TECNICO',
                     'IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO']
    if not any(m in body_text.upper() for m in [m.upper() for m in MARCADORES_RT] + ['REQUERENTE:']):
        return {}

    def achar_linha_apos(marcador, texto):
        idx = texto.find(marcador)
        if idx < 0:
            return ""
        resto = texto[idx + len(marcador):]
        linhas = [l.strip() for l in resto.split("\n") if l.strip()]
        return linhas[0] if linhas else ""

    # ── Requerente ──────────────────────────────────────────────────
    nome_req, cpf_req = "", ""
    for marcador_req in ["REQUERENTE:", "Requerente:"]:
        linha_req = achar_linha_apos(marcador_req, body_text)
        if linha_req:
            partes = linha_req.split(" - CPF:")
            nome_req = partes[0].strip()
            if len(partes) > 1:
                cpf_req = partes[1].split(" - ")[0].strip()
            break

    # ── RT — formato novo: "NOME - CPF: X - E-MAIL: Y" ─────────────
    nome_rt, cpf_rt, email_rt, tel_rt, formacao, registro = "", "", "", "", "", ""

    for marcador_rt in ["RESPONSÁVEL TÉCNICO:", "RESPONSAVEL TECNICO:",
                        "RESPONSÁVEL TÉCNICO", "RESPONSAVEL TECNICO"]:
        linha_rt = achar_linha_apos(marcador_rt, body_text)
        if linha_rt:
            partes_rt = linha_rt.split(" - CPF:")
            nome_rt   = partes_rt[0].strip()
            if len(partes_rt) > 1:
                resto_rt = partes_rt[1]
                cpf_rt   = resto_rt.split(" - ")[0].strip()
                m_email  = re.search(r'E-MAIL[:\s]+([^\s\n]+)', resto_rt, re.IGNORECASE)
                email_rt = m_email.group(1).strip() if m_email else ""
                m_tel    = re.search(r'TELEFONE[:\s]+([^\-\n]+)', resto_rt, re.IGNORECASE)
                tel_rt   = m_tel.group(1).strip() if m_tel else ""
            break

    # ── RT — formato antigo: seção "IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO" ──
    if not nome_rt:
        marcador_ant = 'IDENTIFICAÇÃO DO RESPONSÁVEL TÉCNICO'
        if marcador_ant in body_text:
            idx   = body_text.index(marcador_ant)
            secao = body_text[idx:]
            fim   = secao.find('DADOS DO ENQUADRAMENTO')
            if fim > 0:
                secao = secao[:fim]
            def achar(padrao):
                m = re.search(padrao, secao, re.IGNORECASE)
                return m.group(1).strip() if m else ""
            nome_rt  = achar(r'Nome/Raz[aã]o social\s*:?\s*\n\s*([^\n]+)')
            cpf_rt   = achar(r'CPF/CNPJ\s*:?\s*\n\s*([^\n]+)')
            tel_rt   = achar(r'Telefone\s*:?\s*\n\s*([^\n]+)')
            email_rt = achar(r'E-mail\s*:?\s*\n\s*([^\n]+)')
            formacao = achar(r'Forma[çc][aã]o Profissional\s*[:\-]\s*([^\n\|\-]+)')
            registro = achar(r'Registro Profissional\s*[:\-]\s*([^\n]+)')

    # Formação e registro — busca geral
    if not formacao:
        m_f = re.search(r'Forma[çc][aã]o Profissional\s*[:\-]\s*([^\n\|\-]+)', body_text, re.IGNORECASE)
        if m_f:
            formacao = m_f.group(1).strip()
    if not registro:
        m_r = re.search(r'Registro Profissional\s*[:\-]\s*([^\n]+)', body_text, re.IGNORECASE)
        if m_r:
            registro = m_r.group(1).strip()

    if not nome_rt and not cpf_rt:
        return {}

    # ── Número do requerimento ───────────────────────────────────────
    # Aparece como "Nº: 12769/2026" no cabeçalho do documento,
    # ou como IDENTIFICAÇÃO: "5271-2015" na tabela de dados,
    # ou como ORIGEM: "12769/2026" nos dados cadastrais do processo.
    num_req = ""

    # Padrão 1: "Nº: 12769/2026" ou "N°: 12769/2026"
    m_n = re.search(r'N[º°oo]\.?\s*:?\s*([\d]+/\d{4})', body_text, re.IGNORECASE)
    if m_n:
        num_req = m_n.group(1).strip()

    # Padrão 2: campo IDENTIFICAÇÃO na tabela (ex: "5271-2015" ou "5803/2026")
    if not num_req:
        linha_id = achar_linha_apos("IDENTIFICAÇÃO:", body_text)
        if not linha_id:
            linha_id = achar_linha_apos("IDENTIFICAÇÃO", body_text)
        if linha_id:
            # A linha fica como "REQUERIMENTO 5271-2015 DIGITAL PÚBLICO"
            # ou só "5271-2015"
            m_id = re.search(r'(?:REQUERIMENTO\s+)?(\S+[-/]\S+)', linha_id, re.IGNORECASE)
            if m_id:
                num_req = m_id.group(1).strip()

    # Padrão 3: campo ORIGEM nos dados do processo (ex: "12769/2026")
    if not num_req:
        m_orig = re.search(r'ORIGEM[:\s]+(\d+/\d{4})', body_text, re.IGNORECASE)
        if m_orig:
            num_req = m_orig.group(1).strip()

    # Padrão 4: REFERÊNCIA nos dados do processo
    if not num_req:
        m_ref = re.search(r'REFERÊNCIA[:\s]+(\d+/\d{4})', body_text, re.IGNORECASE)
        if m_ref:
            num_req = m_ref.group(1).strip()

    resultado = {
        'resp_tecnico_nome':     nome_rt,
        'resp_tecnico_cpf':      cpf_rt,
        'resp_tecnico_tel':      tel_rt,
        'resp_tecnico_email':    email_rt,
        'resp_tecnico_formacao': formacao,
        'resp_tecnico_registro': registro,
    }
    if num_req:
        resultado['num_requerimento_doc'] = num_req
    if nome_req:
        resultado['nome_requerente_doc'] = nome_req
    if cpf_req:
        resultado['cpf_requerente_doc']  = cpf_req
    return resultado


def _extrair_resp_tecnico(driver):
    """
    Extrai dados do Responsável Técnico e do Requerente da página
    de detalhe do requerimento no SIGAM.

    Formato real da página (protocolo/impressao.asp):
      REQUERENTE:
      Nome Completo - CPF: 000.000.000-00 - E-MAIL: email@dominio.com
      RESPONSÁVEL TÉCNICO:
      NOME RT - CPF: 000.000.000-00 - E-MAIL: email@dominio.com
    """
    try:
        body_text = _get_page_text(driver)

        if not body_text:
            print("[!] Página vazia. URL: " + driver.current_url)
            return {}


        resultado = _extrair_rt_do_texto(body_text)
        if resultado:
            print("  -> RT: " + resultado.get('resp_tecnico_nome','') +
                  " | CPF: " + resultado.get('resp_tecnico_cpf',''))
        else:
            pass  # RT not in this page, will try next
        return resultado

    except Exception as exc:
        print('[!] Erro ao extrair RT: ' + str(exc))
        return {}


# ==========================================
#           ROTA PARA O SIGAM
# ==========================================
@app.route('/api/buscar-sigam', methods=['POST', 'OPTIONS'])
def buscar_sigam():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    driver = None

    try:
        dados      = request.json
        ano        = dados.get('ano')
        orgao      = dados.get('orgao')
        sequencial = dados.get('sequencial')

        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-gpu')
        options.add_argument('--log-level=3')

        print("Iniciando navegador...")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        wait = WebDriverWait(driver, 30)

        def buscar_texto(xpath, timeout=10):
            try:
                el = WebDriverWait(driver, timeout).until(
                    EC.presence_of_element_located((By.XPATH, xpath))
                )
                return el.text.strip()
            except:
                return ""

        # ── HELPER: entrar no frame principal se SIGAM usar frameset ──
        def entrar_frame_principal():
            driver.switch_to.default_content()
            frames = driver.find_elements(By.TAG_NAME, 'frame')
            if not frames:
                frames = driver.find_elements(By.TAG_NAME, 'iframe')
            if not frames:
                return
            for nome in ('main', 'conteudo', 'content', 'MAIN', 'corpo'):
                try:
                    driver.switch_to.frame(nome)
                    return
                except:
                    pass
            try:
                driver.switch_to.frame(frames[0])
            except:
                pass

        # ── LOGIN ────────────────────────────────────────────────────
        print("Passo 1: Login SIGAM...")
        driver.get("https://sigam.to.gov.br/proton/login.asp")
        wait.until(EC.presence_of_element_located((By.NAME, "txt_login"))).send_keys("05424940196")
        driver.find_element(By.NAME, "txt_senha").send_keys("Catarina050125-")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        wait.until(lambda d: 'login.asp' not in d.current_url)
        time.sleep(3)
        print("  -> URL pos-login: " + driver.current_url)
        entrar_frame_principal()

        # ── MENU PROCESSO → PESQUISA SIMPLES ─────────────────────────
        print("Passo 2: Menu Processo → Pesquisa Simples...")
        wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="processo"]/span'))).click()
        time.sleep(2)
        wait.until(EC.element_to_be_clickable(
            (By.XPATH, '//*[@id="sidebar-wrapper"]/div[3]/div/ul/li[9]/ul/li[5]/a')
        )).click()
        time.sleep(3)

        # ── PREENCHER PESQUISA ────────────────────────────────────────
        def preencher_campo(campo, valor):
            driver.execute_script("arguments[0].value = '';", campo)
            time.sleep(0.2)
            campo.click()
            campo.send_keys(Keys.CONTROL + 'a')
            campo.send_keys(Keys.DELETE)
            time.sleep(0.2)
            for ch in str(valor):
                campo.send_keys(ch)
                time.sleep(0.07)
            time.sleep(0.3)

        print("Passo 3: Preenchendo campos (ano=" + str(ano) + ")...")
        campo_ano = wait.until(EC.presence_of_element_located((By.XPATH, '//*[@id="txt_numero_ano"]')))
        preencher_campo(campo_ano, ano)
        preencher_campo(driver.find_element(By.XPATH, '//*[@id="txt_numero_orgao"]'), orgao)
        preencher_campo(driver.find_element(By.XPATH, '//*[@id="txt_numero_sequencial"]'), sequencial)

        print("Passo 4: Enviando pesquisa...")
        driver.find_element(By.XPATH, '//*[@id="wrapper"]/div[3]/div/div/div/form').submit()
        time.sleep(5)

        try:
            alert = driver.switch_to.alert
            msg = alert.text
            alert.accept()
            return jsonify({'sucesso': False, 'mensagem': msg})
        except:
            pass

        # ── Extrai cod_protocolo da URL (body está vazio — é frameset) ─
        url_pos_submit = driver.current_url
        print("  -> URL após submit: " + url_pos_submit)
        m_cod = re.search(r'cod_protocolo=(\d+)', url_pos_submit)
        cod_protocolo = m_cod.group(1) if m_cod else ""
        print("  -> cod_protocolo: " + cod_protocolo)

        # Número do processo: tenta entrar em cada frame e buscar o texto
        numero_processo = ""

        def tentar_extrair_processo():
            """Tenta ler o número do processo varrendo todos os frames."""
            nonlocal numero_processo
            # Página principal primeiro
            for tentativa_xpath in [
                '//*[@id="wrapper"]/div[3]/div/div/div/table/tbody/tr[2]',
                '//table/tbody/tr[2]',
            ]:
                try:
                    el = driver.find_element(By.XPATH, tentativa_xpath)
                    m = re.match(r'(\d{4}/\d+/\d+)', el.text.strip())
                    if m:
                        numero_processo = m.group(1)
                        return
                except:
                    pass
            # Dentro de frames
            for tag in ('frame', 'iframe'):
                frs = driver.find_elements(By.TAG_NAME, tag)
                for i, fr in enumerate(frs):
                    try:
                        driver.switch_to.frame(fr)
                        for xp in [
                            '//*[@id="wrapper"]/div[3]/div/div/div/table/tbody/tr[2]',
                            '//table/tbody/tr[2]',
                        ]:
                            try:
                                el = driver.find_element(By.XPATH, xp)
                                m = re.match(r'(\d{4}/\d+/\d+)', el.text.strip())
                                if m:
                                    numero_processo = m.group(1)
                                    driver.switch_to.default_content()
                                    return
                            except:
                                pass
                        driver.switch_to.default_content()
                    except:
                        try: driver.switch_to.default_content()
                        except: pass

        driver.switch_to.default_content()
        tentar_extrair_processo()
        if not numero_processo and cod_protocolo:
            numero_processo = "(cod=" + cod_protocolo + ")"
        print("  -> Processo: " + numero_processo)

        if not cod_protocolo:
            raise Exception("cod_protocolo não encontrado na URL: " + url_pos_submit)

        janela_principal = driver.current_window_handle
        janela_docs      = driver.current_window_handle

        # ── PASSO 5: entrar nos frames da página de resultados e ──────
        # coletar todos os hrefs que apontem para documentos do processo
        print("Passo 5: Coletando links de documentos nos frames da página...")
        numero_requerimento = ""
        dados_rt            = {}
        ultimo_href         = ""

        def coletar_links_documento(contexto_txt=""):
            """
            Varre a página atual (e seus frames) em busca de hrefs que
            apontem para documentos juntados ao processo.
            Retorna lista de (texto, href) ordenada por posição na página.
            """
            candidatos = []

            def _buscar_no_contexto(label=""):
                try:
                    links = driver.find_elements(By.XPATH, '//a[@href]')
                    for a in links:
                        href = (a.get_attribute('href') or '').strip()
                        txt  = a.text.strip()
                        # Links de documentos: qualquer URL com cod_protocolo ou impressao.asp
                        if ('area=documento' in href or
                            'impressao.asp' in href or
                            ('cod_protocolo' in href and href != driver.current_url)):
                            candidatos.append((txt, href))
                except:
                    pass

            # Página principal
            driver.switch_to.default_content()
            _buscar_no_contexto('principal')

            # Dentro de frames
            for tag in ('frame', 'iframe'):
                frs = driver.find_elements(By.TAG_NAME, tag)
                for i, fr in enumerate(frs):
                    try:
                        driver.switch_to.frame(fr)
                        _buscar_no_contexto('frame-' + str(i))
                        # Frames aninhados (até 2 níveis)
                        sub = driver.find_elements(By.TAG_NAME, 'frame') + \
                              driver.find_elements(By.TAG_NAME, 'iframe')
                        for sf in sub:
                            try:
                                driver.switch_to.frame(sf)
                                _buscar_no_contexto('subframe')
                                driver.switch_to.parent_frame()
                            except:
                                try: driver.switch_to.parent_frame()
                                except: pass
                        driver.switch_to.default_content()
                    except:
                        try: driver.switch_to.default_content()
                        except: pass

            return candidatos

        links_doc = coletar_links_documento()
        print("  -> Links de documentos encontrados: " + str(len(links_doc)))

        # ── Identifica documentos juntados pelo padrão do SIGAM ─────
        # Os links de documentos juntados têm:
        #   impressao_processo.asp?cod_protocolo=XXXX&area=  (cod diferente do processo)
        # Os botões de ação (ALTERAR, ASSINAR etc) têm outros padrões.
        # Estratégia: coletar todos os cod_protocolo diferentes do processo,
        # ordenados por aparição — o ÚLTIMO é o documento mais recente.
        docs_juntados = []
        vistos = set()
        for t, h in links_doc:
            m_cod = re.search(r'cod_protocolo=(\d+)', h)
            if not m_cod:
                continue
            cp = m_cod.group(1)
            # Ignora o próprio processo e links de ação (alterar, assinar, etc)
            acoes = ('alterar.asp', 'assinar.asp', 'cancelar.asp', 'distribuir.asp',
                     'movimentar.asp', 'comentar.asp', 'vincular.asp', 'pendencia.asp',
                     'responder.asp', 'enquadramento.asp', 'arquivar.asp')
            if cp == cod_protocolo:
                continue
            if any(a in h.lower() for a in acoes):
                continue
            if cp not in vistos:
                vistos.add(cp)
                docs_juntados.append((t.strip(), h, cp))

        print("  -> Documentos juntados identificados: " + str(len(docs_juntados)))
        if docs_juntados:
            # Pega o ÚLTIMO documento juntado (mais recente = maior posição na lista).
            # O último requerimento é o que contém os dados atuais do RT.
            # Se o último for um processo-filho (outro processo juntado), abrimos
            # ele também e buscamos o requerimento dentro.
            t_req, h_req, cp_req = docs_juntados[-1]
            numero_requerimento = t_req or ("cod=" + cp_req)
            ultimo_href = ("https://sigam.to.gov.br/proton/protocolo/impressao_processo.asp"
                           "?cod_protocolo=" + cp_req + "&area=processo")
            print("  -> Último doc juntado: cod=" + cp_req + " | " + ultimo_href)
            # Loga todos para referência
        else:
            print("  -> Nenhum documento juntado identificado ainda")

        # ── PASSO 5B: se não achou nenhum link, tenta ler a página de ─
        # documentos via URL construída com cod_protocolo. O SIGAM tem
        # a página de consulta de documentos em /proton/protocolo/pesquisar_doc.asp
        if not ultimo_href:
            print("Passo 5B: Tentando URLs alternativas de documentos...")
            urls_alternativas = [
                "https://sigam.to.gov.br/proton/protocolo/pesquisar_doc.asp?cod_protocolo=" + cod_protocolo,
                "https://sigam.to.gov.br/proton/documento/pesquisar.asp?cod_protocolo=" + cod_protocolo,
                "https://sigam.to.gov.br/proton/protocolo/juntado.asp?cod_protocolo=" + cod_protocolo,
            ]
            for url_alt in urls_alternativas:
                try:
                    driver.switch_to.default_content()
                    driver.get(url_alt)
                    time.sleep(3)
                    entrar_frame_principal()
                    src = driver.page_source
                    if '<body></body>' not in src and len(src) > 500:
                        print("  -> Conteúdo em: " + url_alt)
                        with open("debug_detalhar.txt", "w", encoding="utf-8") as _f:
                            _f.write("URL: " + url_alt + "\n\n" + src[:15000])
                        links_alt = coletar_links_documento()
                        if links_alt:
                            links_doc = links_alt
                            numero_requerimento, ultimo_href = links_alt[-1]
                            print("  -> Encontrado em URL alternativa: " + numero_requerimento)
                            break
                    else:
                        print("  -> Vazio: " + url_alt)
                except Exception as e_alt:
                    print("  -> Erro " + url_alt[:60] + ": " + str(e_alt)[:60])

        # ── PASSO 6: construir URL do requerimento via cod_protocolo ──
        # Se ainda não tiver href, usa o padrão do SIGAM que já confirmamos
        # funcionar: o cod_protocolo do requerimento está nos links area=documento.
        # Como fallback final, abrimos a própria página do processo e extraímos
        # o texto diretamente dos frames.
        if not ultimo_href:
            print("Passo 6: Fallback — lendo texto dos frames da página atual...")
            driver.switch_to.default_content()
            driver.get("https://sigam.to.gov.br/proton/protocolo/"
                       "impressao_processo.asp?cod_protocolo=" + cod_protocolo + "&area=processo")
            time.sleep(4)

            texto_frames = ""
            for tag in ('frame', 'iframe'):
                frs = driver.find_elements(By.TAG_NAME, tag)
                for fr in frs:
                    try:
                        driver.switch_to.frame(fr)
                        t = driver.find_element(By.TAG_NAME, 'body').text
                        if len(t) > len(texto_frames):
                            texto_frames = t
                        # Sub-frames
                        for sf in driver.find_elements(By.TAG_NAME, 'frame') + \
                                  driver.find_elements(By.TAG_NAME, 'iframe'):
                            try:
                                driver.switch_to.frame(sf)
                                st = driver.find_element(By.TAG_NAME, 'body').text
                                if len(st) > len(texto_frames):
                                    texto_frames = st
                                # Coleta links nos sub-frames
                                sub_links = driver.find_elements(By.XPATH, '//a[@href]')
                                for a in sub_links:
                                    href = a.get_attribute('href') or ''
                                    txt  = a.text.strip()
                                    if 'area=documento' in href:
                                        links_doc.append((txt, href))
                                        print("  -> [subframe] doc: " + txt[:50] + " | " + href[:80])
                                driver.switch_to.parent_frame()
                            except:
                                try: driver.switch_to.parent_frame()
                                except: pass
                        driver.switch_to.default_content()
                    except:
                        try: driver.switch_to.default_content()
                        except: pass

            if links_doc:
                numero_requerimento, ultimo_href = links_doc[-1]
                print("  -> Link encontrado nos subframes: " + numero_requerimento)
            elif texto_frames:
                print("  -> Texto dos frames (" + str(len(texto_frames)) + " chars), tentando extração direta...")
                with open("debug_page_rt.txt", "w", encoding="utf-8") as _f:
                    _f.write("=== URL frames: " + driver.current_url + "\n\n")
                    _f.write(texto_frames[:8000])

        # ── PASSO 6B: processos antigos — busca via URL de pesquisa ───
        # Processos de 2015 podem ter documentos em URL diferente.
        # Tenta construir a URL do requerimento a partir do número do processo.
        if not ultimo_href:
            print("Passo 6B: Tentando buscar documento via pesquisa de documentos...")
            urls_busca = [
                # Pesquisa de documentos do processo diretamente
                "https://sigam.to.gov.br/proton/documento/pesquisar.asp?txt_numero_protocolo=" + numero_processo.replace("/", "%2F"),
                # Página de juntados por cod_protocolo (formato antigo)
                "https://sigam.to.gov.br/proton/protocolo/listar_juntados.asp?cod_protocolo=" + cod_protocolo,
                # Formulário de impressão de processos antigos
                "https://sigam.to.gov.br/proton/protocolo/impressao_processo.asp?cod_protocolo=" + cod_protocolo,
            ]
            for url_b in urls_busca:
                try:
                    driver.switch_to.default_content()
                    driver.get(url_b)
                    time.sleep(3)
                    # Varre todos os frames em busca de links
                    links_b = coletar_links_documento()
                    src_b   = driver.page_source
                    print("  -> " + url_b[:80] + " → " + str(len(links_b)) + " links, " + str(len(src_b)) + " chars HTML")
                    if links_b:
                        numero_requerimento, ultimo_href = links_b[-1]
                        print("  -> Encontrado: " + numero_requerimento + " | " + ultimo_href[:80])
                        break
                    # Salva para diagnóstico se não vazio
                    if '<body></body>' not in src_b and len(src_b) > 500:
                        with open("debug_6b_" + url_b.split("=")[-1][:20] + ".txt", "w", encoding="utf-8") as _f:
                            _f.write("URL: " + url_b + "\n\n" + src_b[:10000])
                        print("    -> HTML salvo para diagnóstico")
                except Exception as e_b:
                    print("  -> Erro: " + str(e_b)[:80])

        # ── PASSO 7: abrir o requerimento e extrair dados do RT ────────
        # impressao_processo.asp é frameset — precisa varrer sub-frames.
        # Tenta também impressao.asp (formato novo de documentos).
        def varrer_frames_rt():
            """Varre frames recursivamente buscando dados do RT."""
            result = _extrair_resp_tecnico(driver)
            if result:
                return result
            for tag in ('frame', 'iframe'):
                try:
                    frs = driver.find_elements(By.TAG_NAME, tag)
                except:
                    frs = []
                for i, fr in enumerate(frs):
                    try:
                        driver.switch_to.frame(fr)
                        r = _extrair_resp_tecnico(driver)
                        if r:
                            driver.switch_to.default_content()
                            return r
                        # Sub-frames
                        for tag2 in ('frame', 'iframe'):
                            try:
                                sfrs = driver.find_elements(By.TAG_NAME, tag2)
                            except:
                                sfrs = []
                            for j, sf in enumerate(sfrs):
                                try:
                                    driver.switch_to.frame(sf)
                                    r2 = _extrair_resp_tecnico(driver)
                                    if r2:
                                        driver.switch_to.default_content()
                                        return r2
                                    driver.switch_to.parent_frame()
                                except:
                                    try: driver.switch_to.parent_frame()
                                    except: pass
                        driver.switch_to.default_content()
                    except:
                        try: driver.switch_to.default_content()
                        except: pass
            return {}

        _visitados_rt = set()  # evita loops entre processos que se referenciam

        def buscar_rt_em_cod(cp, nivel=0):
            """
            Abre o documento/processo com cod_protocolo=cp e tenta extrair o RT.
            Se a página for um processo (tiver documentos juntados), entra no
            último deles recursivamente (até 2 níveis).
            """
            if not cp or nivel > 3 or cp in _visitados_rt:
                return {}
            _visitados_rt.add(cp)

            url_proc = ("https://sigam.to.gov.br/proton/protocolo/impressao_processo.asp"
                        "?cod_protocolo=" + cp + "&area=processo")
            url_doc  = ("https://sigam.to.gov.br/proton/protocolo/impressao.asp"
                        "?cod_protocolo=" + cp + "&area=documento")

            for url_tentar in [url_doc, url_proc]:
                print("Passo 7: Abrindo cod=" + cp + " | " + url_tentar)
                driver.switch_to.default_content()
                driver.get(url_tentar)
                time.sleep(5)
                print("  -> URL atual: " + driver.current_url)

                # Tenta extrair RT diretamente
                rt = varrer_frames_rt()
                if rt:
                    print("  -> RT encontrado em: " + url_tentar)
                    return rt

                # Se não achou RT, verifica se a página é um processo com documentos juntados
                # Coleta docs juntados desta página usando a mesma lógica do Passo 5
                docs_filhos = []
                vistos_filhos = set()
                try:
                    todos_links = driver.find_elements(By.XPATH, '//a[@href]')
                    acoes = ('alterar.asp','assinar.asp','cancelar.asp','distribuir.asp',
                             'movimentar.asp','comentar.asp','vincular.asp','pendencia.asp',
                             'responder.asp','enquadramento.asp','arquivar.asp')
                    for a in todos_links:
                        h = (a.get_attribute('href') or '').strip()
                        m = re.search(r'cod_protocolo=(\d+)', h)
                        if not m:
                            continue
                        cp_filho = m.group(1)
                        if cp_filho == cp or cp_filho in vistos_filhos or cp_filho == cod_protocolo:
                            continue
                        if any(ac in h.lower() for ac in acoes):
                            continue
                        vistos_filhos.add(cp_filho)
                        docs_filhos.append(cp_filho)
                except:
                    pass

                if docs_filhos:
                    # Dentro de um processo-filho, tenta cada documento
                    # começando pelo primeiro (requerimento original) e depois
                    # o último (requerimento mais recente). Para no primeiro que tiver RT.
                    print("  -> Processo-filho com " + str(len(docs_filhos)) + " docs juntados: " + str(docs_filhos))
                    # Tenta do ÚLTIMO para o PRIMEIRO — requerimento mais recente tem RT mais atual
                    for cp_filho in reversed(docs_filhos):
                        print("  -> Tentando doc filho: cod=" + cp_filho)
                        rt = buscar_rt_em_cod(cp_filho, nivel + 1)
                        if rt:
                            return rt

            return {}

        if ultimo_href:
            cp_doc = re.search(r'cod_protocolo=(\d+)', ultimo_href)
            cp_doc = cp_doc.group(1) if cp_doc else ""
            dados_rt = buscar_rt_em_cod(cp_doc)
        else:
            print("Passo 7: Nenhum href — tentando RT da página atual...")
            dados_rt = varrer_frames_rt()


        print("  -> RT extraído: " + str(bool(dados_rt)))

        # Fecha aba de documentos e volta à principal se necessário
        try:
            if driver.current_window_handle != janela_principal:
                driver.close()
                driver.switch_to.window(janela_principal)
        except:
            pass

        # ── Busca o número do requerimento no PRIMEIRO doc juntado ──────
        # O requerimento original (1º doc) sempre tem o Nº do requerimento.
        # O RT pode vir de outro doc mais recente, mas o número vem do 1º.
        num_req_final = dados_rt.get('num_requerimento_doc', '')
        if not num_req_final and docs_juntados:
            cp_primeiro = docs_juntados[0][2]  # (txt, href, cp) → cp
            print("  -> Buscando Nº req no 1º doc juntado: cod=" + cp_primeiro)
            try:
                driver.switch_to.default_content()
                url_req_orig = ("https://sigam.to.gov.br/proton/protocolo/impressao.asp"
                                "?cod_protocolo=" + cp_primeiro + "&area=documento")
                driver.get(url_req_orig)
                time.sleep(4)
                txt_orig = _get_page_text(driver)
                if txt_orig:
                    # Padrão 1: REQUERIMENTO NNNNN/AAAA na tabela de dados
                    m1 = re.search(r"REQUERIMENTO\s+([\d][\d\-/]+[\d])", txt_orig, re.IGNORECASE)
                    if m1:
                        num_req_final = m1.group(1).strip()
                    # Padrão 2: Nº: 12769/2026
                    if not num_req_final:
                        m2 = re.search(r"N[\u00ba\u00b0]\s*:?\s*([\d]+/\d{4})", txt_orig, re.IGNORECASE)
                        if m2:
                            num_req_final = m2.group(1).strip()
                    # Padrão 3: IDENTIFICAÇÃO: XXXXX/AAAA
                    if not num_req_final:
                        m3 = re.search(r"IDENTIFICAÇÃO[:\s]+([\d][\d\-/]+[\d])", txt_orig, re.IGNORECASE)
                        if m3:
                            num_req_final = m3.group(1).strip()
                    # Padrão 4: ORIGEM: NNNNN/AAAA
                    if not num_req_final:
                        m4 = re.search(r"ORIGEM[:\s]+([\d]+/\d{4})", txt_orig, re.IGNORECASE)
                        if m4:
                            num_req_final = m4.group(1).strip()
                            num_req_final = m5.group(1).strip()
                    print("  -> Nº req encontrado: " + (num_req_final or "NÃO ENCONTRADO"))

            except Exception as e_nreq:
                print("  -> Erro ao buscar Nº req: " + str(e_nreq)[:60])

        if num_req_final:
            dados_rt['num_requerimento_doc'] = num_req_final

        print("SUCESSO! RT extraído: " + str(bool(dados_rt)) + " | Nº req: " + (num_req_final or "-"))
        return jsonify({
            'sucesso':             True,
            'numero_processo':     numero_processo,
            'numero_requerimento': numero_requerimento,
            **dados_rt
        })

    except Exception as e:
        print("[!] Erro geral: " + str(e))
        if driver:
            try:
                driver.save_screenshot("erro_sigam.png")
            except:
                pass
        return jsonify({'sucesso': False, 'mensagem': str(e)})

    finally:
        if driver:
            driver.quit()


# ==========================================
#           INICIALIZADOR
# ==========================================
if __name__ == '__main__':
    app.run(port=3000, debug=True)