"""
agent/tools/spec_validator.py
Validador e autocorretor sintático do .spec ANTES de rodar o Certora.
Corrige erros comuns deterministicamente, sem chamar a IA.
"""
import re


def remover_rules_vazias(spec_cvl: str) -> tuple[str, list[str]]:
    """Remove rules que contém apenas comentários ou estão vazias."""
    correcoes = []
    resultado = []
    linhas = spec_cvl.split('\n')
    i = 0
    while i < len(linhas):
        linha = linhas[i]
        if re.match(r'\s*rule\s+(\w+)', linha):
            nome = re.match(r'\s*rule\s+(\w+)', linha).group(1)
            bloco = [linha]
            depth = linha.count('{') - linha.count('}')
            j = i + 1
            while j < len(linhas) and depth > 0:
                bloco.append(linhas[j])
                depth += linhas[j].count('{') - linhas[j].count('}')
                j += 1
            bloco_str = '\n'.join(bloco)
            sem_comentarios = re.sub(r'//[^\n]*', '', bloco_str)
            sem_header = re.sub(r'rule\s+\w+', '', sem_comentarios)
            sem_espacos = re.sub(r'[\s{}();]', '', sem_header)
            if not sem_espacos:
                correcoes.append(f"Rule '{nome}' removida — estava vazia (só comentários)")
                i = j
                continue
            resultado.extend(bloco)
            i = j
        else:
            resultado.append(linha)
            i += 1
    return '\n'.join(resultado), correcoes


def deduplicar_spec(spec_cvl: str) -> tuple[str, list[str]]:
    """
    Remove blocos duplicados do spec:
    - Remove methods{} duplicados (mantém só o primeiro)
    - Remove rules com nome duplicado (mantém só a primeira)
    """
    correcoes = []
    linhas = spec_cvl.split('\n')

    # 1. Remove methods{} duplicados
    methods_count = 0
    in_methods = False
    skip_methods = False
    novas = []
    i = 0
    while i < len(linhas):
        linha = linhas[i]
        if re.match(r'\s*methods\s*\{', linha):
            methods_count += 1
            if methods_count > 1:
                skip_methods = True
                correcoes.append(f"Linha {i+1}: removido bloco methods{{}} duplicado")
            else:
                in_methods = True
        if skip_methods:
            if '}' in linha:
                skip_methods = False
            i += 1
            continue
        if in_methods and '}' in linha:
            in_methods = False
        novas.append(linha)
        i += 1

    # 2. Remove rules duplicadas
    linhas2 = novas
    novas2 = []
    rules_vistas = set()
    skip_rule = False
    depth = 0
    for linha in linhas2:
        m = re.match(r'\s*rule\s+(\w+)', linha)
        if m:
            nome = m.group(1)
            if nome in rules_vistas:
                skip_rule = True
                depth = 0
                correcoes.append(f"Rule '{nome}' duplicada removida")
            else:
                rules_vistas.add(nome)
                skip_rule = False
                depth = 0
        if skip_rule:
            depth += linha.count('{') - linha.count('}')
            if depth <= 0 and '}' in linha:
                skip_rule = False
            continue
        novas2.append(linha)

    return '\n'.join(novas2), correcoes


def corrigir_spec(spec_cvl: str) -> tuple[str, list[str]]:
    """
    Aplica correções automáticas linha a linha no spec CVL.
    Retorna (spec_corrigido, lista_de_correcoes_aplicadas).
    """
    correcoes = []
    linhas = spec_cvl.split('\n')
    novas_linhas = list(linhas)

    for i, linha in enumerate(linhas):
        stripped = linha.strip()

        if not stripped or stripped.startswith('//'):
            continue

        # CORREÇÃO 1: chamada de função SEM @withrevert antes de assert lastReverted
        proxima = ""
        for j in range(i + 1, len(linhas)):
            s = linhas[j].strip()
            if s:
                proxima = s
                break

        if proxima == "assert lastReverted;" and '@withrevert' not in linha:
            m = re.match(r'^(\s*)(\w+)(\(.*\));$', linha)
            if m:
                indent, func, args_com_parens = m.group(1), m.group(2), m.group(3)
                novas_linhas[i] = f"{indent}{func}@withrevert{args_com_parens};"
                correcoes.append(f"Linha {i+1}: @withrevert adicionado em '{func}(...)'")

        # CORREÇÃO 1b: remove receive/constructor/fallback do methods{}
        if re.match(r'^\s*function\s+(receive|constructor|fallback)\s*\(', linha):
            novas_linhas[i] = ''
            correcoes.append(f"Linha {i+1}: removido '{linha.strip()}' — receive/constructor/fallback não vão no methods{{}}")
            continue

        # CORREÇÃO 1c: payable() casting nas rules
        if 'payable(' in linha and 'methods' not in linha:
            nova = re.sub(r'payable\(([^)]+)\)', r'\1', novas_linhas[i])
            if nova != novas_linhas[i]:
                novas_linhas[i] = nova
                correcoes.append(f"Linha {i+1}: removido casting payable(...)")

        # CORREÇÃO 2: block.timestamp/block.number sem e.
        if 'block.timestamp' in linha and 'e.block.timestamp' not in linha:
            novas_linhas[i] = novas_linhas[i].replace('block.timestamp', 'e.block.timestamp')
            correcoes.append(f"Linha {i+1}: block.timestamp → e.block.timestamp")

        if 'block.number' in linha and 'e.block.number' not in linha:
            novas_linhas[i] = novas_linhas[i].replace('block.number', 'e.block.number')
            correcoes.append(f"Linha {i+1}: block.number → e.block.number")

    return '\n'.join(novas_linhas), correcoes


def validar_spec(spec_cvl: str) -> tuple[bool, list[str]]:
    """
    Valida o spec após autocorreção e retorna (valido, lista_de_avisos).
    """
    erros = []
    linhas = spec_cvl.split('\n')

    for i, linha in enumerate(linhas):
        stripped = linha.strip()

        # Verifica lastReverted sem @withrevert
        if 'assert lastReverted' in stripped:
            for j in range(i - 1, -1, -1):
                ant = linhas[j].strip()
                if ant:
                    if '@withrevert' not in ant:
                        erros.append(f"Linha {j+1}: falta @withrevert antes de assert lastReverted")
                    break

        # Verifica mathint no methods{}
        if 'mathint' in stripped and 'returns' in stripped and 'envfree' in stripped:
            erros.append(f"Linha {i+1}: mathint proibido no methods{{}}")

    # Verifica rules sem assert no final
    in_rule = False
    rule_lines = []
    rule_name = ""
    for i, linha in enumerate(linhas):
        stripped = linha.strip()
        if re.match(r'^rule\s+\w+', stripped):
            in_rule = True
            rule_name = stripped
            rule_lines = []
        if in_rule:
            rule_lines.append((i, stripped))
            if stripped == '}':
                for _, l in reversed(rule_lines[:-1]):
                    if l:
                        if not (l.startswith('assert') or l.startswith('satisfy')):
                            erros.append(f"Rule '{rule_name}': última instrução não é assert/satisfy: '{l}'")
                        break
                in_rule = False

    # Verifica envfree chamadas com env
    envfree_funcs = set()
    in_methods = False
    for linha in linhas:
        if 'methods' in linha and '{' in linha:
            in_methods = True
        if in_methods and '}' in linha:
            in_methods = False
        if in_methods and 'envfree' in linha:
            m = re.match(r'\s*function\s+(\w+)', linha)
            if m:
                envfree_funcs.add(m.group(1))

    for i, linha in enumerate(linhas):
        for func in envfree_funcs:
            if re.search(rf'{func}\s*\(e\)', linha):
                erros.append(f"Linha {i+1}: '{func}(e)' — função envfree não aceita env")

    return len(erros) == 0, erros