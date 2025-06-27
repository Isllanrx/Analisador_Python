# 🚀 Analisador de Código Python Pro

**Sistema completo para análise e correção automática de código Python com paralelismo inteligente.**

## 📋 Funcionalidades Principais

### 🔍 **Análise Avançada**
- **Violações PEP8**: Detecção completa de problemas de formatação
- **Complexidade de código**: Identificação de funções com alta complexidade ciclomática
- **Imports não utilizados**: Detecção precisa de imports desnecessários
- **Problemas de segurança**: Análise com Bandit para vulnerabilidades
- **Documentação**: Verificação de docstrings ausentes ou fracas
- **Código duplicado**: Detecção de duplicações com jscpd (se disponível)

### 🔧 **Correção Automática**
- **Paralelismo inteligente**: Usa metade dos núcleos disponíveis (evita travamentos)
- **Detecção automática**: Núcleos, ambiente virtual, dependências
- **Formatação PEP8**: Correção automática com autopep8
- **Organização de imports**: Ordenação com isort
- **Compatibilidade total**: Windows (.bat) e Linux/Mac (.sh)

### 📊 **Relatórios e Métricas**
- **Ranking de arquivos**: Por criticidade (🔴 Crítica, 🟡 Média, 🟢 Baixa)
- **Estatísticas detalhadas**: Tempo, arquivos, problemas por categoria
- **Relatório JSON**: Dados completos para integração com outras ferramentas
- **Métricas de maintainability**: Análise de manutenibilidade do código

### ⚡ **Performance**
- **Cache inteligente**: Evita reprocessamento desnecessário
- **Processamento paralelo**: Até 8 workers simultâneos na análise
- **Timeouts dinâmicos**: Ajuste automático para projetos grandes
- **Escalabilidade**: Suporte a projetos com 10.000+ arquivos

## 🎯 Uso Rápido

## Basta colocar o arquivo .py na raiz do seu projeto e rodar ele!
### **1.0 Dependencias**

``` pip install flake8 radon vulture bandit autopep8 black isort tqdm ```
``` npm install -g jscpd ```

### **1.1 Análise Completa**
```bash
python Analise_codigo_pro.py
```

### **2. Correção Automática**
```bash
# Windows
auto_correcao.bat

# Linux/Mac  
./auto_correcao.sh
```

### **3. Ciclo Completo**
```bash
python Analise_codigo_pro.py    # Analisa e gera scripts
auto_correcao.bat               # Corrige automaticamente
python Analise_codigo_pro.py    # Verifica melhorias
```

## 📈 Resultados Típicos

### **Exemplo Real:**
- **ANTES**: 🔴 Crítica - 144 pontos, 132 violações PEP8
- **DEPOIS**: 🟢 Baixa - 13 pontos, 1 violação PEP8
- **MELHORIA**: 91% redução geral, 99.2% correção PEP8

## 🛠️ Arquivos Gerados

| Arquivo | Descrição |
|---------|-----------|
| `relatorio_analise_projeto_pro.json` | Relatório completo em JSON |
| `auto_correcao.bat` | Script Windows com paralelismo |
| `auto_correcao.sh` | Script Linux/Mac |

## 🔧 Configurações Automáticas

### **Detecção de Sistema**
- **Núcleos disponíveis**: Detecta automaticamente (ex: 8 → usa 4)
- **Ambiente virtual**: Ativa venv/.venv se encontrado
- **Dependências**: Instala autopep8/isort automaticamente
- **Encoding**: UTF-8 com fallback para problemas

### **Paralelismo Inteligente**
- **Análise**: Até 8 workers simultâneos
- **Correção PEP8**: 4 núcleos (controlado)
- **Organização imports**: 4 núcleos (controlado)
- **Anti-travamento**: Usa metade dos núcleos disponíveis

## 📋 Dependências

### **Obrigatórias** (instalação automática):
- `autopep8` - Correção PEP8
- `isort` - Organização de imports

### **Opcionais** (funcionalidades extras):
- `bandit` - Análise de segurança
- `tqdm` - Barra de progresso
- `jscpd` - Detecção de código duplicado
- `unimport` - Remoção de imports não usados

## 🎪 Funcionalidades Avançadas

### **Sistema de Cache**
- **MD5 hash**: Evita reprocessamento de arquivos inalterados
- **Tipos de análise**: Cache separado por tipo (PEP8, segurança, etc.)
- **Performance**: 3-5x mais rápido em execuções subsequentes

### **Configurações Empresariais**
- **Timeouts dinâmicos**: 20s padrão, 30s para projetos >1000 arquivos
- **Exclusões inteligentes**: venv, __pycache__, .git, node_modules
- **Feedback visual**: Progress bar e estatísticas em tempo real

### **Compatibilidade**
- **Windows**: PowerShell e CMD
- **Linux/Mac**: Bash e Zsh
- **Ambientes virtuais**: venv, .venv, conda
- **Execução**: Terminal ou clique duplo

## 🏆 Casos de Uso

### **Desenvolvimento Individual**
- Análise rápida antes de commits
- Correção automática de formatação
- Melhoria contínua da qualidade

### **Equipes e CI/CD**
- Integração em pipelines
- Padronização de código
- Relatórios de qualidade

### **Projetos Grandes**
- Análise escalável (10K+ arquivos)
- Cache para performance
- Processamento paralelo otimizado