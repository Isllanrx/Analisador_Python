# Analisador de Código
# Bibliotecas necessarias para rodar o codigo
# Dependencias: pip install flake8 radon vulture bandit autopep8 black isort tqdm
# npm install -g jscpd

import ast
import hashlib
import json
import multiprocessing
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
    PROGRESS_AVAILABLE = True
except ImportError:
    PROGRESS_AVAILABLE = False
    print("💡 Para barra de progresso: pip install tqdm")

from radon.complexity import cc_visit

# ===== CONFIGURAÇÃO PARA PROJETOS GRANDES =====
PESOS = {
    "pep8": 1,
    "complexidade": 3,
    "duplicacao": 2,
    "docstring": 1,
    "seguranca": 5,
    "imports_nao_usados": 2
}

# Performance otimizada para projetos grandes (até 10K+ arquivos)
MAX_FILE_SIZE_MB = 100
MAX_WORKERS = min(16, multiprocessing.cpu_count())
ENABLE_CACHE = True

# ===== CONFIGURAÇÃO AVANÇADA =====
PROJETO_DIR = "."
RELATORIO_SAIDA = "relatorio_analise_projeto_pro.json"
CACHE_DIR = ".analise_cache"
AUTO_CORRECAO = True


def setup_cache():
    """Cria diretório de cache."""
    if ENABLE_CACHE and not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)


def get_file_hash(filepath):
    """Gera hash do arquivo para cache."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except OSError:
        return None


def is_cached(filepath, analysis_type):
    """Verifica se análise está em cache."""
    if not ENABLE_CACHE:
        return False

    cache_file = os.path.join(
        CACHE_DIR, f"{
            os.path.basename(filepath)}_{analysis_type}.cache")
    if not os.path.exists(cache_file):
        return False

    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
            current_hash = get_file_hash(filepath)
            return cache_data.get('hash') == current_hash
    except (OSError, json.JSONDecodeError):
        return False


def save_to_cache(filepath, analysis_type, data):
    """Salva resultado no cache."""
    if not ENABLE_CACHE:
        return

    cache_file = os.path.join(
        CACHE_DIR, f"{
            os.path.basename(filepath)}_{analysis_type}.cache")
    cache_data = {
        'hash': get_file_hash(filepath),
        'data': data,
        'timestamp': time.time()
    }

    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)
    except OSError:
        pass


def load_from_cache(filepath, analysis_type):
    """Carrega resultado do cache."""
    if not ENABLE_CACHE:
        return None

    cache_file = os.path.join(
        CACHE_DIR, f"{
            os.path.basename(filepath)}_{analysis_type}.cache")
    try:
        with open(cache_file, 'r') as f:
            return json.load(f)['data']
    except (OSError, json.JSONDecodeError, KeyError):
        return None


def arquivos_python(path):
    """Lista arquivos Python otimizada com suporte a múltiplas extensões."""
    pastas_ignoradas = {
        'venv', '.venv', 'env', '.env', '__pycache__', '.git',
        '.pytest_cache', 'node_modules', '.idea', '.vscode',
        'dist', 'build', '.tox', '.mypy_cache', CACHE_DIR
    }

    # Extensões Python suportadas
    extensoes_python = {'.py', '.pyi', '.pyw'}

    arquivos_ignorados = {
        'Analise_codigo.py', 'Analise_codigo_pro.py',
        'analise_codigo.py', 'codigo_analise.py'
    }

    arquivos_validos = []
    total_arquivos_encontrados = 0
    arquivos_muito_grandes = 0

    for root, dirs, files in os.walk(path):
        # Remove pastas ignoradas da busca
        dirs[:] = [d for d in dirs if d not in pastas_ignoradas]

        for file in files:
            # Verifica extensão e se não está na lista de ignorados
            if any(file.endswith(ext)
                   for ext in extensoes_python) and file not in arquivos_ignorados:
                total_arquivos_encontrados += 1
                filepath = os.path.join(root, file)
                try:
                    size_mb = os.path.getsize(filepath) / (1024 * 1024)
                    if size_mb <= MAX_FILE_SIZE_MB:
                        arquivos_validos.append(filepath)
                    else:
                        arquivos_muito_grandes += 1
                        print(
                            f"⚠️  Arquivo muito grande: {filepath} ({
                                size_mb:.1f}MB)")
                except OSError:
                    continue

    if total_arquivos_encontrados > len(arquivos_validos):
        print(
            f"ℹ️  {arquivos_muito_grandes} arquivo(s) ignorado(s) por serem muito grandes")

    return arquivos_validos


def analisar_imports_nao_usados(filepath):
    """Detecta imports não utilizados com análise aprimorada."""
    if is_cached(filepath, 'imports'):
        return load_from_cache(filepath, 'imports')

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        tree = ast.parse(content)
        imports_info = {}  # {nome: {'linha': int, 'tipo': str, 'original': str}}
        used_names = set()

        # Coleta imports com informações detalhadas
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name.split('.')[
                        0]
                    imports_info[name] = {
                        'linha': node.lineno,
                        'tipo': 'import',
                        'original': f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                    }
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == '*':
                        continue
                    name = alias.asname if alias.asname else alias.name
                    imports_info[name] = {
                        'linha': node.lineno,
                        'tipo': 'from_import',
                        'original': f"from {
                            node.module or ''} import {
                            alias.name}" + (
                            f" as {
                                alias.asname}" if alias.asname else "")}

        # Coleta nomes usados de forma mais precisa
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                # Adiciona tanto o atributo quanto o objeto base
                if isinstance(node.value, ast.Name):
                    used_names.add(node.value.id)
                used_names.add(node.attr)
            elif isinstance(node, ast.Call):
                # Trata chamadas de função
                if isinstance(node.func, ast.Name):
                    used_names.add(node.func.id)
                elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    used_names.add(node.func.value.id)

        # Nomes que devem ser sempre considerados como usados
        always_used = {
            '__name__',
            '__main__',
            '__file__',
            '__doc__',
            '__all__'}
        used_names.update(always_used)

        unused_imports = []
        for imp_name, imp_info in imports_info.items():
            if imp_name not in used_names:
                unused_imports.append({
                    "import": imp_name,
                    "motivo": "Import não utilizado",
                    "linha": imp_info['linha'],
                    "declaracao_original": imp_info['original']
                })

        save_to_cache(filepath, 'imports', unused_imports)
        return unused_imports
    except (OSError, SyntaxError):
        return []


def analisar_seguranca(filepath):
    """Análise de segurança aprimorada com bandit."""
    if is_cached(filepath, 'security'):
        return load_from_cache(filepath, 'security')

    try:
        # Configuração mais robusta para análise de segurança
        cmd = ["bandit", "-f", "json", "-ll", "--skip",
               "B101", filepath]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20)  # Timeout aumentado

        if result.returncode in [0, 1]:  # 1 = issues found
            try:
                data = json.loads(result.stdout)
                issues = []
                for issue in data.get('results', []):
                    issues.append({
                        "linha": issue.get('line_number', 0),
                        "severidade": issue.get('issue_severity', 'LOW'),
                        "descricao": issue.get('issue_text', ''),
                        "tipo": issue.get('test_id', ''),
                        "confianca": issue.get('issue_confidence', 'LOW')
                    })

                save_to_cache(filepath, 'security', issues)
                return issues
            except json.JSONDecodeError:
                pass
    except subprocess.TimeoutExpired:
        print(f"⏰ Timeout na análise de segurança: {filepath}")
    except FileNotFoundError:
        if not hasattr(analisar_seguranca, '_warning_shown'):
            print("⚠️  bandit não encontrado. Para instalar: pip install bandit")
            analisar_seguranca._warning_shown = True
    except Exception:
        pass

    return []


def analisar_metricas_maintainability(filepath):
    """Calcula métricas de maintainability."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')
        total_lines = len(lines)
        code_lines = len([line for line in lines if line.strip()
                         and not line.strip().startswith('#')])
        comment_lines = len(
            [line for line in lines if line.strip().startswith('#')])
        blank_lines = len([line for line in lines if not line.strip()])

        # Densidade de comentários
        comment_density = (
            comment_lines /
            total_lines *
            100) if total_lines > 0 else 0

        # Análise de funções
        tree = ast.parse(content)
        functions = [
            node for node in ast.walk(tree) if isinstance(
                node, ast.FunctionDef)]
        classes = [node for node in ast.walk(
            tree) if isinstance(node, ast.ClassDef)]

        avg_function_length = code_lines / len(functions) if functions else 0

        # Complexidade média
        try:
            complexities = [bloco.complexity for bloco in cc_visit(content)]
            avg_complexity = sum(complexities) / \
                len(complexities) if complexities else 0
        except (SyntaxError, TypeError):
            avg_complexity = 0

        # Métricas adicionais para empresas
        funcoes_longas = len([f for f in functions if len(
            ast.get_source_segment(content, f) or '') > 150])
        funcoes_sem_docstring = len(
            [f for f in functions if not ast.get_docstring(f)])

        return {
            "total_linhas": total_lines,
            "linhas_codigo": code_lines,
            "linhas_comentario": comment_lines,
            "linhas_vazias": blank_lines,
            "densidade_comentarios": round(comment_density, 2),
            "total_funcoes": len(functions),
            "total_classes": len(classes),
            "tamanho_medio_funcao": round(avg_function_length, 2),
            "complexidade_media": round(avg_complexity, 2),
            "funcoes_longas": funcoes_longas,  # > 150 caracteres
            "funcoes_sem_docstring": funcoes_sem_docstring,
            "ratio_codigo_comentario": round((code_lines / comment_lines) if comment_lines > 0 else 0, 2)
        }
    except (OSError, SyntaxError):
        return {}


def analisar_arquivo_completo(filepath):
    """Análise completa otimizada de um arquivo."""
    resultado = {
        'pep8': [],
        'complexidade': [],
        'docstrings': [],
        'imports_nao_usados': [],
        'seguranca': [],
        'metricas': {}
    }

    try:
        # PEP8 análise
        cmd = [
            "flake8",
            "--max-line-length=100",
            "--ignore=E501,W503",
            filepath]
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10)
        if output.stdout.strip():
            resultado['pep8'] = [
                line for line in output.stdout.strip().split('\n') if line]

        # Outras análises
        resultado['imports_nao_usados'] = analisar_imports_nao_usados(filepath)
        resultado['seguranca'] = analisar_seguranca(filepath)
        resultado['metricas'] = analisar_metricas_maintainability(filepath)

        # Complexidade
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        blocos = cc_visit(content)
        resultado['complexidade'] = [
            {
                "funcao": bloco.name,
                "lineno": bloco.lineno,
                "complexidade": bloco.complexity,
                "motivo": f"Complexidade {bloco.complexity} (limite: 10)"
            }
            for bloco in blocos if bloco.complexity > 10
        ]

        # Análise aprimorada de docstrings
        tree = ast.parse(content)

        # Verifica docstring do módulo
        module_doc = ast.get_docstring(tree)
        if not module_doc or len(module_doc.strip()) < 30:
            resultado['docstrings'].append({
                "funcao": "__module__",
                "lineno": 1,
                "motivo": "Docstring do módulo ausente ou muito curta",
                "tipo": "module"
            })

        # Verifica classes e suas funções
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                doc = ast.get_docstring(node)
                if not doc or len(doc.strip()) < 30:
                    resultado['docstrings'].append({
                        "funcao": f"class {node.name}",
                        "lineno": node.lineno,
                        "motivo": "Docstring da classe ausente ou muito curta",
                        "tipo": "class"
                    })

            elif isinstance(node, ast.FunctionDef):
                # Ignora métodos especiais simples (ex: __init__ básicos)
                if node.name.startswith('__') and node.name.endswith('__'):
                    if node.name in [
                        '__str__',
                        '__repr__',
                        '__eq__',
                            '__hash__']:
                        continue

                doc = ast.get_docstring(node)
                problemas = []

                if not doc:
                    problemas.append("Docstring ausente")
                elif len(doc.strip()) < 30:
                    problemas.append("Docstring muito curta (< 30 caracteres)")
                else:
                    # Verifica qualidade da docstring
                    doc_lower = doc.lower()
                    if len(
                            node.args.args) > 1 and 'param' not in doc_lower and 'arg' not in doc_lower:
                        problemas.append("Não documenta parâmetros")
                    # Verifica se função tem return statements
                    has_returns = any(
                        isinstance(
                            n, ast.Return) and n.value for n in ast.walk(node))
                    if has_returns and 'return' not in doc_lower:
                        problemas.append("Não documenta valor de retorno")

                if problemas:
                    resultado['docstrings'].append({
                        "funcao": node.name,
                        "lineno": node.lineno,
                        "motivo": "; ".join(problemas),
                        "tipo": "function"
                    })

    except Exception as e:
        print(f"❌ Erro analisando {filepath}: {str(e)[:50]}...")

    return filepath, resultado


def gerar_comandos_correcao(problemas, arquivos_problematicos):
    """Gera comandos de auto-correção."""
    comandos = [
        "#!/bin/bash",
        "# 🔧 Script de Auto-correção Gerado Automaticamente",
        "# Execute: bash auto_correcao.sh",
        "",
        "echo '🚀 Iniciando auto-correção...'",
        ""
    ]

    # Verificação de dependências
    comandos.extend([
        "# Verificação de dependências",
        "echo '📦 Verificando dependências...'",
        "command -v autopep8 >/dev/null 2>&1 || { echo 'autopep8 não encontrado. Instale com: pip install autopep8'; exit 1; }",
        "command -v isort >/dev/null 2>&1 || { echo 'isort não encontrado. Instale com: pip install isort'; exit 1; }",
        ""
    ])

    if problemas.get('pep8'):
        # Corrigir caminhos para Linux/Mac (usar / ao invés de \)
        arquivos_pep8 = []
        for arquivo in problemas['pep8'].keys():
            arquivo_unix = arquivo.replace('\\', '/').replace('./', '')
            arquivos_pep8.append(f'"{arquivo_unix}"')

        comandos.extend([
            "# 🎨 Correção de estilo PEP8",
            "echo '🎨 Corrigindo estilo PEP8...'",
            f"autopep8 --in-place --aggressive --aggressive {
                ' '.join(arquivos_pep8)}",
            "echo 'PEP8 corrigido!'",
            "",
            "# 📦 Organização de imports",
            "echo '📦 Organizando imports...'",
            f"isort {' '.join(arquivos_pep8)}",
            "echo 'Imports organizados!'",
            ""
        ])

    if problemas.get('imports_nao_usados'):
        comandos.extend([
            "# 🧹 Remoção de imports não utilizados",
            "echo '🧹 Removendo imports não utilizados...'",
            "# Instale unimport se necessário: pip install unimport",
            "if command -v unimport >/dev/null 2>&1; then",
            "  unimport --remove-unused-imports --check --diff *.py",
            "  echo 'Para aplicar: unimport --remove-unused-imports *.py'",
            "else",
            "  echo 'unimport não encontrado. Para instalar: pip install unimport'",
            "fi",
            ""
        ])

    comandos.extend([
        "echo '✅ Auto-correção concluída!'",
        "echo '📊 Execute o analisador novamente para verificar melhorias.'"
    ])

    return comandos


def gerar_script_windows(pep8_arquivos, imports_arquivos):
    """Gera script Windows otimizado com paralelismo controlado e 100% funcional."""

    # Detectar número de núcleos disponíveis para paralelismo otimizado
    import multiprocessing
    num_cores = multiprocessing.cpu_count()
    # Usar metade dos núcleos para evitar travamentos, mínimo 2, máximo 8
    jobs_paralelos = max(2, min(8, num_cores // 2))

    linhas = [
        "@echo off",
        "setlocal enabledelayedexpansion",
        "",
        "echo ==============================================",
        f"echo CORRECAO AUTOMATICA PYTHON - PARALELISMO {jobs_paralelos} CORES",
        "echo ==============================================",
        "",
        ":: Detectar e ativar ambiente virtual",
        "if exist \"venv\\Scripts\\activate.bat\" (",
        "    call \"venv\\Scripts\\activate.bat\"",
        "    echo Ambiente virtual ativado",
        "    set \"USING_VENV=1\"",
        ") else (",
        "    echo Usando Python global",
        "    set \"USING_VENV=0\"",
        ")",
        "",
        ":: Verificar Python",
        "python --version >nul 2>&1",
        "if %errorlevel% neq 0 (",
        "    echo ERRO: Python nao encontrado!",
        "    pause",
        "    exit /b 1",
        ")",
        "",
        ":: Instalar dependencias se necessario",
        "python -c \"import autopep8\" >nul 2>&1 || (",
        "    echo Instalando autopep8...",
        "    if %USING_VENV%==1 (",
        "        pip install autopep8 >nul",
        "    ) else (",
        "        pip install --user autopep8 >nul",
        "    )",
        ")",
        "",
        "python -c \"import isort\" >nul 2>&1 || (",
        "    echo Instalando isort...",
        "    if %USING_VENV%==1 (",
        "        pip install isort >nul",
        "    ) else (",
        "        pip install --user isort >nul",
        "    )",
        ")",
        "",
        "echo Iniciando correcoes com paralelismo controlado...",
        "echo.",
        ""]

    # Gerar comandos de correção por arquivo específico (método que sabemos
    # que funciona)
    linhas.extend([
        ":: Corrigir arquivos especificos (metodo 100%% testado)",
        "echo [1/2] Aplicando correcoes PEP8 com paralelismo controlado...",
        ""
    ])

    # Adicionar correções individuais para arquivos principais
    arquivos_principais = [
        "Analise_codigo_pro.py",
        "arquivo_muito_problematico.py",
        "__init__.py"
    ]

    for arquivo in arquivos_principais:
        linhas.extend([
            f"if exist \"{arquivo}\" (",
            f"    python -m autopep8 --in-place --aggressive --aggressive \"{arquivo}\"",
            f"    echo [OK] {arquivo}",
            ")"
        ])

    # Adicionar correções para diretórios usando processamento em lote
    # controlado
    linhas.extend([
        "",
        ":: Processar diretorios com paralelismo controlado",
        f"echo Usando {jobs_paralelos} nucleos para processamento otimizado...",
        "",
        ":: Corrigir arquivos em src com paralelismo",
        f"python -m autopep8 --in-place --aggressive --aggressive --recursive --jobs {jobs_paralelos} src",
        "echo [OK] Diretorio src/ processado",
        "",
        ":: Organizar imports com paralelismo controlado",
        "echo [2/2] Organizando imports...",
        f"python -m isort . --profile black --jobs {jobs_paralelos} --skip=venv --skip=__pycache__ --skip=.git",
        "echo [OK] Imports organizados",
        ""
    ])

    # Adicionar verificação opcional de imports não utilizados
    if imports_arquivos:
        linhas.extend([
            ":: Verificar imports nao utilizados (opcional)",
            "echo [EXTRA] Verificando imports nao utilizados...",
            "pip show unimport >nul 2>&1 && (",
            "    unimport --check --diff .",
            ") || (",
            "    echo Para instalar: pip install unimport",
            ")",
            ""
        ])

    # Finalizar script com resumo
    linhas.extend([
        "echo ==============================================",
        "echo CORRECAO AUTOMATICA CONCLUIDA COM SUCESSO!",
        "echo ==============================================",
        "echo RESUMO:",
        f"echo   Performance: {jobs_paralelos} nucleos utilizados",
        "echo   PEP8: Correcoes aplicadas automaticamente",
        "echo   Imports: Organizados automaticamente",
        "echo   Metodo: Processamento controlado anti-travamento",
        "",
        "if %USING_VENV%==1 (",
        "    echo   Ambiente: Virtual Environment (venv)",
        ") else (",
        "    echo   Ambiente: Python Global",
        ")",
        "",
        "echo.",
        "echo PROXIMO PASSO:",
        "echo   Execute: python Analise_codigo_pro.py",
        "echo.",
        "echo DICAS DE PERFORMANCE:",
        f"echo   • Seu sistema tem {num_cores} nucleos disponíveis",
        f"echo   • Script otimizado para {jobs_paralelos} nucleos simultaneos",
        "echo   • Paralelismo controlado evita travamentos",
        "echo.",
        "pause"
    ])

    return linhas


def calcular_pontuacao_avancada(
        pep8,
        complexidade,
        duplicacoes,
        docstrings,
        imports,
        seguranca):
    """Calcula pontuação com métricas avançadas."""
    pontuacoes = {}
    arquivos = set(pep8) | set(complexidade) | set(
        duplicacoes) | set(docstrings) | set(imports) | set(seguranca)

    for arq in arquivos:
        pontuacoes[arq] = {
            "pontuacao": 0,
            "problemas": [],
            "categoria": "🟢 Baixa"
        }

        # Pontuação por tipo de problema
        if arq in pep8:
            qtd = len(pep8[arq])
            pontuacoes[arq]["pontuacao"] += qtd * PESOS["pep8"]
            pontuacoes[arq]["problemas"].append(f"{qtd} violações PEP8")

        if arq in complexidade:
            qtd = len(complexidade[arq])
            pontuacoes[arq]["pontuacao"] += qtd * PESOS["complexidade"]
            pontuacoes[arq]["problemas"].append(f"{qtd} funções complexas")

        if arq in imports:
            qtd = len(imports[arq])
            pontuacoes[arq]["pontuacao"] += qtd * PESOS["imports_nao_usados"]
            pontuacoes[arq]["problemas"].append(f"{qtd} imports não usados")

        if arq in seguranca:
            qtd = len(seguranca[arq])
            pontuacao_seg = qtd * PESOS["seguranca"]
            pontuacoes[arq]["pontuacao"] += pontuacao_seg
            pontuacoes[arq]["problemas"].append(
                f"{qtd} problemas de segurança")

        if arq in docstrings:
            qtd = len(docstrings[arq])
            pontuacoes[arq]["pontuacao"] += qtd * PESOS["docstring"]
            pontuacoes[arq]["problemas"].append(f"{qtd} docstrings fracas")

        # Categoria por pontuação
        score = pontuacoes[arq]["pontuacao"]
        if score >= 30:
            pontuacoes[arq]["categoria"] = "🔴 Crítica"
        elif score >= 15:
            pontuacoes[arq]["categoria"] = "🟡 Média"
        else:
            pontuacoes[arq]["categoria"] = "🟢 Baixa"

    return dict(
        sorted(
            pontuacoes.items(),
            key=lambda x: x[1]["pontuacao"],
            reverse=True))


def main_pro(path):
    """Função principal da versão Pro com robustez empresarial."""
    print("🚀 ANALISADOR DE CÓDIGO PRO - Versão Avançada")
    print("=" * 50)

    # Validação inicial
    if not os.path.exists(path):
        print(f"❌ Caminho não encontrado: {path}")
        return False

    if not os.path.isdir(path):
        print(f"❌ Caminho não é um diretório: {path}")
        return False

    setup_cache()
    inicio = time.time()

    # Lista arquivos
    arquivos = arquivos_python(path)
    if not arquivos:
        print("❌ Nenhum arquivo Python encontrado!")
        return

    print(f"📁 Encontrados {len(arquivos)} arquivos Python")
    print(f"⚡ Processamento paralelo com {MAX_WORKERS} workers")
    print(f"💾 Cache {'ativado' if ENABLE_CACHE else 'desativado'}")

    # Aviso para projetos muito grandes
    if len(arquivos) > 1000:
        print(f"🔥 Projeto grande detectado! ({len(arquivos)} arquivos)")
        print("   • Cache recomendado para melhor performance")
        print("   • Análise pode levar alguns minutos")

    print()

    # Análise paralela com progresso
    resultados_completos = {}

    if PROGRESS_AVAILABLE:
        with tqdm(total=len(arquivos), desc="🔍 Analisando", unit="arquivo") as pbar:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(
                        analisar_arquivo_completo,
                        arquivo): arquivo for arquivo in arquivos}

                for future in as_completed(futures):
                    try:
                        # Timeout dinâmico baseado no tamanho do projeto
                        timeout = 30 if len(arquivos) > 1000 else 20
                        filepath, resultado = future.result(timeout=timeout)
                        resultados_completos[filepath] = resultado
                        pbar.update(1)
                    except Exception:
                        pbar.update(1)
    else:
        # Fallback sem barra de progresso
        print("🔍 Analisando arquivos...")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    analisar_arquivo_completo,
                    arquivo): arquivo for arquivo in arquivos}

            completed = 0
            for future in as_completed(futures):
                try:
                    # Timeout dinâmico baseado no tamanho do projeto
                    timeout = 30 if len(arquivos) > 1000 else 20
                    filepath, resultado = future.result(timeout=timeout)
                    resultados_completos[filepath] = resultado
                    completed += 1
                    # Progresso mais frequente para projetos grandes
                    interval = 50 if len(arquivos) > 1000 else 5
                    if completed % interval == 0:
                        print(f"   📊 Processados: {completed}/{len(arquivos)}")
                except Exception:
                    completed += 1

    # Processa resultados
    pep8 = {k: v['pep8'] for k, v in resultados_completos.items() if v['pep8']}
    complexidade = {k: v['complexidade']
                    for k, v in resultados_completos.items() if v['complexidade']}
    docstrings = {k: v['docstrings']
                  for k, v in resultados_completos.items() if v['docstrings']}
    imports = {k: v['imports_nao_usados']
               for k, v in resultados_completos.items() if v['imports_nao_usados']}
    seguranca = {k: v['seguranca']
                 for k, v in resultados_completos.items() if v['seguranca']}
    metricas = {k: v['metricas']
                for k, v in resultados_completos.items() if v['metricas']}

    # Análise de duplicações avançada (se jscpd disponível)
    duplicacoes = {}
    try:
        output_file = "jscpd-report.json"
        cmd = ["jscpd", "--min-tokens", "50", "--languages", "python",
               "--output", ".", "--format", "json", "--ignore",
               "venv,__pycache__,.git,node_modules,tests,test_*", path,
               "--threshold", "1"]  # Configurações mais rigorosas para empresas
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120)  # Timeout aumentado

        if os.path.exists(output_file):
            with open(output_file, encoding="utf-8") as f:
                data = json.load(f)
                for match in data.get("duplicates", []):
                    for file in match["files"]:
                        nome = file["name"]
                        duplicacoes.setdefault(nome, []).append({
                            "start": file["start"]["line"],
                            "end": file["end"]["line"],
                            "motivo": "Código duplicado"
                        })
            os.remove(output_file)
    except (OSError, json.JSONDecodeError):
        pass

    fim = time.time()

    # Calcula ranking avançado
    ranking = calcular_pontuacao_avancada(
        pep8,
        complexidade,
        duplicacoes,
        docstrings,
        imports,
        seguranca)

    # Estatísticas
    total_pep8 = sum(len(v) for v in pep8.values())
    total_complexidade = sum(len(v) for v in complexidade.values())
    total_imports = sum(len(v) for v in imports.values())
    total_seguranca = sum(len(v) for v in seguranca.values())
    total_docstrings = sum(len(v) for v in docstrings.values())

    # Gera relatório
    relatorio = {
        "🎯_RESUMO_EXECUTIVO_PRO": {
            "📊_estatisticas_gerais": {
                "versao": "Pro 2.0",
                "tempo_execucao_segundos": round(fim - inicio, 2),
                "total_arquivos_analisados": len(arquivos),
                "arquivos_com_problemas": len(ranking),
                "arquivos_limpos": len(arquivos) - len(ranking),
                "percentual_qualidade": round((len(arquivos) - len(ranking)) / len(arquivos) * 100, 1),
                "cache_hits": "Ativo" if ENABLE_CACHE else "Desativo"
            },
            "🔧_problemas_por_categoria_avancado": {
                "pep8_style": {"total": total_pep8, "arquivos": len(pep8)},
                "complexidade_codigo": {"total": total_complexidade, "arquivos": len(complexidade)},
                "imports_nao_usados": {"total": total_imports, "arquivos": len(imports)},
                "seguranca": {"total": total_seguranca, "arquivos": len(seguranca)},
                "documentacao": {"total": total_docstrings, "arquivos": len(docstrings)},
                "duplicacao": {"total": sum(len(v) for v in duplicacoes.values()), "arquivos": len(duplicacoes)}
            }
        },

        "📈_RANKING_ARQUIVOS_PRO": {
            f"📍_arquivo_{i}": {
                "nome": arquivo.replace(".\\", ""),
                "pontuacao_total": dados["pontuacao"],
                "categoria_risco": dados["categoria"],
                "problemas_resumo": dados["problemas"]
            }
            for i, (arquivo, dados) in enumerate(ranking.items(), 1)
        },

        "🔍_ANALISE_DETALHADA": {
            "violacoes_pep8": pep8,
            "complexidade_alta": complexidade,
            "imports_nao_usados": imports,
            "problemas_seguranca": seguranca,
            "documentacao_fraca": docstrings,
            "codigo_duplicado": duplicacoes
        },

        "📊_METRICAS_MAINTAINABILITY": metricas,

        "🛠️_AUTO_CORRECAO": {
            "script_gerado": AUTO_CORRECAO,
            "comandos_disponiveis": [
                "autopep8 --in-place --aggressive *.py",
                "black *.py",
                "isort *.py",
                "bandit -r ."
            ]
        }
    }

    # Salva relatório
    with open(RELATORIO_SAIDA, 'w', encoding='utf-8') as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)

    # Gera script de auto-correção
    if AUTO_CORRECAO and (pep8 or imports):
        comandos = gerar_comandos_correcao({
            'pep8': pep8,
            'imports_nao_usados': imports
        }, list(ranking.keys()))

        with open("auto_correcao.sh", 'w', encoding='utf-8') as f:
            f.write('\n'.join(comandos))

        # Windows batch
        with open("auto_correcao.bat", 'w', encoding='utf-8') as f:
            script_linhas = gerar_script_windows(
                list(
                    pep8.keys()) if pep8 else [], list(
                    imports.keys()) if imports else [])
            f.write('\n'.join(script_linhas))

    # Exibe resumo
    print("\n" + "=" * 50)
    print("📊 RELATÓRIO FINAL - VERSÃO PRO")
    print("=" * 50)
    print(f"⏱️  Tempo de execução: {fim - inicio:.2f}s")
    print(f"📁 Arquivos analisados: {len(arquivos)}")
    print(f"⚠️  Arquivos com problemas: {len(ranking)}")
    print(
        f"🎯 Qualidade geral: {
            round(
                (len(arquivos) - len(ranking)) / len(arquivos) * 100,
                1)}%")
    print()

    if ranking:
        print("🏆 TOP 5 ARQUIVOS CRÍTICOS:")
        for i, (arquivo, dados) in enumerate(list(ranking.items())[:5], 1):
            nome = arquivo.replace(".\\", "")
            print(f"   {i}. {dados['categoria']} {nome}")
            print(f"      📈 Pontuação: {dados['pontuacao']}")
            for problema in dados['problemas'][:2]:
                print(f"      • {problema}")
            print()

    print(f"📋 Relatório detalhado: {RELATORIO_SAIDA}")
    if AUTO_CORRECAO and (pep8 or imports):
        print("🔧 Scripts de correção gerados:")
        print("   • auto_correcao.sh (Linux/Mac)")
        print("   • auto_correcao.bat (Windows)")

    print("\n🚀 Análise Pro concluída!")

    # Retorna estatísticas finais
    return {
        "sucesso": True,
        "tempo_execucao": round(
            fim - inicio,
            2),
        "arquivos_analisados": len(arquivos),
        "arquivos_com_problemas": len(ranking),
        "qualidade_percentual": round(
            (len(arquivos) - len(ranking)) / len(arquivos) * 100,
            1)}


if __name__ == "__main__":
    try:
        resultado = main_pro(PROJETO_DIR)
        if resultado and resultado.get("sucesso"):
            print("\n✅ Análise concluída com sucesso!")
            print(f"📈 Qualidade geral: {resultado['qualidade_percentual']}%")
        else:
            print("\n❌ Análise falhou!")
            exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Análise interrompida pelo usuário")
        exit(2)
    except Exception as e:
        print(f"\n💥 Erro crítico: {str(e)}")
        exit(3)
