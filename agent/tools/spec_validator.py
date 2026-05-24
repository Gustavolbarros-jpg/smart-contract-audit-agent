"""
agent/tools/spec_validator.py
Validador e autocorretor sintático do .spec ANTES de rodar o Certora.
Corrige erros comuns deterministicamente, sem chamar a IA.
"""
import re


def substituir_methods_block(spec_cvl: str, methods_block: str) -> tuple[str, list[str]]:
    """Replace any LLM-generated methods{} with a deterministic one."""
    if not methods_block.strip():
        return spec_cvl, []

    linhas = spec_cvl.split('\n')
    novas = []
    correcoes = []
    inserted = False
    skipping = False
    depth = 0

    for i, linha in enumerate(linhas):
        if not skipping and re.match(r'^\s*methods\s*\{', linha):
            if not inserted:
                novas.extend(methods_block.split('\n'))
                inserted = True
                correcoes.append(f"Linha {i+1}: methods{{}} substituído por bloco determinístico")
            skipping = True
            depth = linha.count('{') - linha.count('}')
            if depth <= 0:
                skipping = False
            continue

        if skipping:
            depth += linha.count('{') - linha.count('}')
            if depth <= 0:
                skipping = False
            continue

        novas.append(linha)

    if not inserted:
        novas = methods_block.split('\n') + [""] + novas
        correcoes.append("methods{} determinístico inserido no início")

    return '\n'.join(novas), correcoes


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


def remover_wrapper_rules(spec_cvl: str) -> tuple[str, list[str]]:
    """Remove o wrapper inválido `rules { ... }`, mantendo cada `rule` no topo."""
    correcoes = []
    linhas = spec_cvl.split('\n')
    novas = []
    in_wrapper = False
    depth = 0

    for i, linha in enumerate(linhas):
        if not in_wrapper and re.match(r'^\s*rules\s*\{\s*$', linha):
            in_wrapper = True
            depth = 1
            correcoes.append(f"Linha {i+1}: removido wrapper inválido rules{{}}")
            continue

        if in_wrapper:
            next_depth = depth + linha.count('{') - linha.count('}')
            if next_depth == 0 and linha.strip() == '}':
                in_wrapper = False
                depth = 0
                continue
            novas.append(linha)
            depth = next_depth
            continue

        novas.append(linha)

    return '\n'.join(novas), correcoes


def _limpar_parametros_methods(params: str) -> str:
    cleaned = []
    for param in params.split(','):
        param = param.strip()
        if not param or param == 'env' or param.startswith('env '):
            continue
        cleaned.append(param)
    return ', '.join(cleaned)


def normalizar_methods_com_corpo(spec_cvl: str) -> tuple[str, list[str]]:
    """Transforma funções com corpo dentro de methods{} em declarações CVL."""
    correcoes = []
    linhas = spec_cvl.split('\n')
    novas = []
    in_methods = False
    skip_body = False
    body_depth = 0

    for i, linha in enumerate(linhas):
        stripped = linha.strip()

        if skip_body:
            body_depth += linha.count('{') - linha.count('}')
            if body_depth <= 0:
                skip_body = False
                body_depth = 0
            continue

        if re.match(r'^\s*methods\s*\{', linha):
            in_methods = True
            novas.append(linha)
            continue

        if in_methods and stripped == '}':
            in_methods = False
            novas.append(linha)
            continue

        if in_methods and re.match(r'^\s*function\s+\w+', linha) and '{' in linha:
            match = re.match(
                r'^(\s*)function\s+(\w+)\s*\(([^)]*)\)\s*external(?:\s+payable)?(?:\s+returns\s*\(([^)]*)\))?.*\{',
                linha,
            )
            if match:
                indent, name, params, returns = match.groups()
                params = _limpar_parametros_methods(params)
                returns_part = f" returns({returns.strip()})" if returns else ""
                novas.append(f"{indent}function {name}({params}) external{returns_part};")
                correcoes.append(f"Linha {i+1}: corpo de function removido dentro de methods{{}}")
                body_depth = linha.count('{') - linha.count('}')
                if body_depth > 0:
                    skip_body = True
                continue

        novas.append(linha)

    return '\n'.join(novas), correcoes


def envolver_blocos_vuln_sem_rule(spec_cvl: str, rule_name_by_id: dict[str, str]) -> tuple[str, list[str]]:
    """Wrap loose statements after // VULN_XXX comments into CVL rule blocks."""
    linhas = spec_cvl.split('\n')
    novas = []
    correcoes = []
    i = 0

    while i < len(linhas):
        linha = linhas[i]
        vuln_match = re.search(r'\b(VULN_\d{3})\b', linha)
        if not vuln_match:
            novas.append(linha)
            i += 1
            continue

        vuln_id = vuln_match.group(1)
        block = []
        j = i + 1
        while j < len(linhas):
            if re.search(r'\bVULN_\d{3}\b', linhas[j]):
                break
            block.append(linhas[j])
            j += 1

        if any(re.match(r'\s*rule\s+\w+', item) for item in block):
            novas.append(linha)
            novas.extend(block)
            i = j
            continue

        statements = [item for item in block if item.strip()]
        rule_name = rule_name_by_id.get(vuln_id, f"rule_{vuln_id.lower()}")
        if statements:
            novas.append(linha)
            novas.append(f"rule {rule_name} {{")
            for item in block:
                if item.strip():
                    novas.append("  " + item.strip())
                else:
                    novas.append(item)
            novas.append("}")
            correcoes.append(f"{vuln_id}: statements soltos envolvidos em rule {rule_name}")
        else:
            novas.append(linha)
            novas.extend(block)
        i = j

    return '\n'.join(novas), correcoes


def quebrar_instrucoes_multiplas(spec_cvl: str) -> tuple[str, list[str]]:
    """Split simple one-line sequences such as `env e; require ...;`."""
    correcoes = []
    novas = []
    in_methods = False

    for i, linha in enumerate(spec_cvl.split('\n')):
        stripped = linha.strip()
        if re.match(r'^\s*methods\s*\{', linha):
            in_methods = True
        if in_methods:
            novas.append(linha)
            if stripped == '}':
                in_methods = False
            continue
        if not stripped or stripped.startswith('//') or stripped in ('{', '}'):
            novas.append(linha)
            continue

        parts = [part.strip() for part in stripped.split(';') if part.strip()]
        if len(parts) <= 1:
            novas.append(linha)
            continue

        indent = re.match(r'^(\s*)', linha).group(1)
        for part in parts:
            novas.append(f"{indent}{part};")
        correcoes.append(f"Linha {i+1}: instruções múltiplas separadas")

    return '\n'.join(novas), correcoes


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

        # CORREÇÃO 1c: CVL methods{} não aceita modificador payable.
        if re.match(r'^\s*function\s+\w+', linha) and ' payable' in linha:
            nova = re.sub(r'\s+payable(?=\s*;)', '', novas_linhas[i])
            nova = nova.replace('address payable', 'address')
            if nova != novas_linhas[i]:
                novas_linhas[i] = nova
                correcoes.append(f"Linha {i+1}: payable removido do methods{{}}")

        # CORREÇÃO 1d: getters e funções com return no methods{} devem ser envfree.
        if re.match(r'^\s*function\s+\w+', linha) and 'returns' in linha and 'envfree' not in linha:
            if novas_linhas[i].rstrip().endswith(';'):
                novas_linhas[i] = novas_linhas[i].rstrip()[:-1].rstrip() + ' envfree;'
                correcoes.append(f"Linha {i+1}: envfree adicionado em função com returns no methods{{}}")

        # CORREÇÃO 1f: payable() casting nas rules
        if 'payable(' in linha and 'methods' not in linha:
            nova = re.sub(r'payable\(([^)]+)\)', r'\1', novas_linhas[i])
            if nova != novas_linhas[i]:
                novas_linhas[i] = nova
                correcoes.append(f"Linha {i+1}: removido casting payable(...)")

        # CORREÇÃO 1g: CVL não deve inicializar address com 0 na declaração.
        m_zero_address = re.match(r'^(\s*)address\s+(\w+)\s*=\s*0\s*;\s*$', linha)
        if m_zero_address:
            novas_linhas[i] = f"{m_zero_address.group(1)}address {m_zero_address.group(2)};"
            correcoes.append(f"Linha {i+1}: inicialização address = 0 removida da declaração")

        # CORREÇÃO 2: block.timestamp/block.number sem e.
        if 'block.timestamp' in linha and 'e.block.timestamp' not in linha:
            novas_linhas[i] = novas_linhas[i].replace('block.timestamp', 'e.block.timestamp')
            correcoes.append(f"Linha {i+1}: block.timestamp → e.block.timestamp")

        if 'block.number' in linha and 'e.block.number' not in linha:
            novas_linhas[i] = novas_linhas[i].replace('block.number', 'e.block.number')
            correcoes.append(f"Linha {i+1}: block.number → e.block.number")

    envfree_funcs = set()
    in_methods = False
    for linha in novas_linhas:
        if 'methods' in linha and '{' in linha:
            in_methods = True
        if in_methods and 'envfree' in linha:
            m = re.match(r'\s*function\s+(\w+)', linha)
            if m:
                envfree_funcs.add(m.group(1))
        if in_methods and '}' in linha:
            in_methods = False

    in_methods = False
    for i, linha in enumerate(novas_linhas):
        stripped = linha.strip()
        if 'methods' in linha and '{' in linha:
            in_methods = True
        if in_methods and '}' in linha:
            in_methods = False
            continue
        if in_methods or stripped.startswith('//'):
            continue

        nova = linha
        for func in envfree_funcs:
            nova = re.sub(rf'\b{func}\s*\[([^\]]+)\]', rf'{func}(\1)', nova)
            nova = re.sub(rf'\b{func}\b(?!\s*\()', f'{func}()', nova)
        if nova != linha:
            novas_linhas[i] = nova
            correcoes.append(f"Linha {i+1}: acesso direto a getter convertido para chamada envfree")

    return '\n'.join(novas_linhas), correcoes


def inserir_requires_zero_address(spec_cvl: str) -> tuple[str, list[str]]:
    """Garante require x == 0 em rules de missing-zero-check."""
    linhas = spec_cvl.split('\n')
    novas = []
    correcoes = []
    in_zero_rule = False
    rule_lines = []
    rule_name = ""

    def flush_rule():
        nonlocal rule_lines, in_zero_rule, rule_name
        if not rule_lines:
            return []

        if not in_zero_rule:
            out = rule_lines
            rule_lines = []
            return out

        address_vars = []
        for line in rule_lines:
            m = re.match(r'\s*address\s+(\w+)\s*;', line)
            if m:
                address_vars.append(m.group(1))

        if not address_vars:
            out = rule_lines
            rule_lines = []
            return out

        has_zero_require = any(
            re.search(rf'\brequire\s+{var}\s*==\s*0\s*;', line)
            for var in address_vars
            for line in rule_lines
        )
        if has_zero_require:
            out = rule_lines
            rule_lines = []
            return out

        target_var = address_vars[0]
        out = []
        inserted = False
        for line in rule_lines:
            if not inserted and '@withrevert' in line:
                indent = re.match(r'^(\s*)', line).group(1)
                out.append(f"{indent}require {target_var} == 0;")
                inserted = True
                correcoes.append(f"Rule '{rule_name}': require {target_var} == 0 inserido")
            out.append(line)

        rule_lines = []
        return out

    previous_comment = ""
    for linha in linhas:
        stripped = linha.strip()

        if stripped.startswith("//"):
            previous_comment = stripped

        rule_match = re.match(r'\s*rule\s+(\w+)', linha)
        if rule_match:
            novas.extend(flush_rule())
            rule_name = rule_match.group(1)
            in_zero_rule = "zero" in rule_name or "missing-zero-check" in previous_comment
            rule_lines = [linha]
            continue

        if rule_lines:
            rule_lines.append(linha)
            if stripped == '}':
                novas.extend(flush_rule())
                in_zero_rule = False
                rule_name = ""
            continue

        novas.append(linha)

    novas.extend(flush_rule())
    return '\n'.join(novas), correcoes


def remover_prefixo_revert_duplicado(spec_cvl: str) -> tuple[str, list[str]]:
    """Remove revert-preludes that cause duplicated env declarations in one rule."""
    linhas = spec_cvl.split('\n')
    novas = []
    correcoes = []
    in_rule = False
    rule_name = ""
    rule_lines = []

    def flush_rule():
        nonlocal rule_lines, in_rule, rule_name
        if not rule_lines:
            return []

        env_indices = [
            idx for idx, line in enumerate(rule_lines)
            if re.match(r'\s*env\s+\w+\s*;', line)
        ]
        if len(env_indices) < 2:
            out = rule_lines
            rule_lines = []
            return out

        first_env = env_indices[0]
        second_env = env_indices[1]
        prelude = rule_lines[first_env:second_env]
        has_revert_prelude = any('@withrevert' in line for line in prelude) and any(
            'assert lastReverted' in line for line in prelude
        )

        if not has_revert_prelude:
            out = rule_lines
            rule_lines = []
            return out

        out = rule_lines[:first_env] + rule_lines[second_env:]
        correcoes.append(f"Rule '{rule_name}': prefixo @withrevert duplicado removido")
        rule_lines = []
        return out

    for linha in linhas:
        rule_match = re.match(r'\s*rule\s+(\w+)', linha)
        if rule_match:
            novas.extend(flush_rule())
            in_rule = True
            rule_name = rule_match.group(1)
            rule_lines = [linha]
            continue

        if in_rule:
            rule_lines.append(linha)
            if linha.strip() == '}':
                novas.extend(flush_rule())
                in_rule = False
                rule_name = ""
            continue

        novas.append(linha)

    novas.extend(flush_rule())
    return '\n'.join(novas), correcoes


def _auth_probe_declarations_and_call(auth_probe: dict) -> tuple[list[str], str]:
    declarations = []
    args = ["e"]
    for index, param in enumerate(auth_probe.get("params", [])):
        param_type = param.get("type", "").strip()
        param_name = param.get("name", "").strip() or f"arg{index}"
        if not param_type:
            continue
        declarations.append(f"  {param_type} {param_name};")
        args.append(param_name)
    return declarations, f"  {auth_probe['name']}@withrevert({', '.join(args)});"


def _is_auth_rule(rule_name: str, previous_comment: str) -> bool:
    normalized = rule_name.replace("-", "_")
    return bool(
        re.search(r"(^|_)auth($|_)", normalized)
        or "tx_origin" in normalized
        or "selfdestruct_auth" in normalized
        or "tx-origin" in previous_comment
        or "suicidal" in previous_comment
    )


def _parse_params(params: str) -> list[dict]:
    parsed = []
    for index, param in enumerate(params.split(',')):
        cleaned = param.strip()
        if not cleaned:
            continue
        cleaned = cleaned.replace("address payable", "address")
        cleaned = re.sub(r"\s+(memory|calldata|storage)\b", "", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        parts = cleaned.split()
        if len(parts) == 1:
            parsed.append({"type": parts[0], "name": f"arg{index}"})
        else:
            parsed.append({"type": " ".join(parts[:-1]), "name": parts[-1]})
    return parsed


def _parse_function_reference(value: str) -> tuple[str, list[dict]]:
    value = (value or "").strip()
    if not value or value in {"modifier/function", "function/modifier"}:
        return "", []

    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", value)
    if match:
        return match.group(1), _parse_params(match.group(2))

    bare = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)$", value)
    if bare:
        return bare.group(1), []

    return "", []


def _parse_methods(methods_block: str) -> dict[str, dict]:
    methods = {}
    for line in methods_block.splitlines():
        match = re.match(
            r"\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*external\b(.*);",
            line.strip(),
        )
        if not match:
            continue
        name, params, tail = match.groups()
        methods[name] = {
            "name": name,
            "params": _parse_params(params),
            "envfree": "envfree" in tail,
        }
    return methods


def _call_match(line: str) -> re.Match | None:
    return re.match(
        r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)(@withrevert)?\s*\(([^;]*)\)\s*;\s*$",
        line,
    )


def _declared_vars(rule_lines: list[str]) -> set[str]:
    declared = set()
    for line in rule_lines:
        match = re.match(
            r"\s*(?:address|bool|string|bytes\d*|uint\d*|int\d*|mathint|env)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=)",
            line,
        )
        if match:
            declared.add(match.group(1))
    return declared


def _zero_address_var(rule_lines: list[str]) -> str:
    for line in rule_lines:
        match = re.search(r"\brequire\s+([A-Za-z_][A-Za-z0-9_]*)\s*==\s*0\s*;", line)
        if match:
            return match.group(1)
    for line in rule_lines:
        match = re.match(r"\s*address\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", line)
        if match:
            return match.group(1)
    return ""


def _safe_var_name(preferred: str, param_type: str, index: int, used: set[str]) -> str:
    candidates = []
    if preferred and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", preferred):
        candidates.append(preferred)
    if param_type.startswith("address"):
        candidates.append("account")
    elif param_type.startswith("uint") or param_type.startswith("int"):
        candidates.append("amount")
    elif param_type.startswith("bool"):
        candidates.append("flag")
    elif param_type.startswith("bytes"):
        candidates.append("data")
    else:
        candidates.append(f"arg{index}")

    for candidate in candidates:
        if candidate not in used:
            used.add(candidate)
            return candidate

    base = candidates[-1]
    suffix = 1
    while f"{base}{suffix}" in used:
        suffix += 1
    name = f"{base}{suffix}"
    used.add(name)
    return name


def _build_target_call(
    expected_name: str,
    params: list[dict],
    rule_lines: list[str],
    withrevert: bool,
    vuln_type: str,
) -> tuple[list[str], str]:
    declared = _declared_vars(rule_lines)
    used = set(declared)
    declarations = []
    args = ["e"]
    zero_var = _zero_address_var(rule_lines) if vuln_type == "missing-zero-check" else ""

    for index, param in enumerate(params):
        param_type = param.get("type", "").strip()
        if not param_type:
            continue
        if index == 0 and zero_var and param_type.startswith("address"):
            var_name = zero_var
        else:
            var_name = param.get("name", "").strip()
            if not var_name or var_name.startswith("arg"):
                var_name = _safe_var_name("", param_type, index, used)
            else:
                used.add(var_name)

        if var_name not in declared:
            declarations.append(f"  {param_type} {var_name};")
            declared.add(var_name)
        args.append(var_name)

    suffix = "@withrevert" if withrevert else ""
    return declarations, f"  {expected_name}{suffix}({', '.join(args)});"


def _rule_vuln_id(previous_comment: str, rule_name: str, id_by_rule_name: dict[str, str]) -> str:
    match = re.search(r"\b(VULN_\d{3})\b", previous_comment)
    if match:
        return match.group(1)
    return id_by_rule_name.get(rule_name, "")


def aplicar_target_binding_rules(
    spec_cvl: str,
    rule_context_by_id: dict[str, dict],
    methods_block: str = "",
) -> tuple[str, list[str]]:
    """Ensure each VULN rule calls the function selected by the formal planner."""
    if not rule_context_by_id:
        return spec_cvl, []

    methods = _parse_methods(methods_block)
    method_names = set(methods)
    id_by_rule_name = {}
    for vuln_id, context in rule_context_by_id.items():
        for rule_name in context.get("rule_names", []):
            id_by_rule_name[rule_name] = vuln_id

    linhas = spec_cvl.split('\n')
    novas = []
    correcoes = []
    previous_comment = ""
    i = 0

    while i < len(linhas):
        linha = linhas[i]
        stripped = linha.strip()
        if stripped.startswith("//"):
            previous_comment = stripped
            novas.append(linha)
            i += 1
            continue

        rule_match = re.match(r"\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)", linha)
        if not rule_match:
            novas.append(linha)
            i += 1
            continue

        rule_name = rule_match.group(1)
        block = [linha]
        depth = linha.count('{') - linha.count('}')
        j = i + 1
        while j < len(linhas) and depth > 0:
            block.append(linhas[j])
            depth += linhas[j].count('{') - linhas[j].count('}')
            j += 1

        vuln_id = _rule_vuln_id(previous_comment, rule_name, id_by_rule_name)
        context = rule_context_by_id.get(vuln_id, {})
        expected_name, expected_params = _parse_function_reference(context.get("function", ""))
        if expected_name and expected_name in methods:
            expected_params = methods[expected_name]["params"]

        if not expected_name or (method_names and expected_name not in method_names):
            novas.extend(block)
            i = j
            continue

        call_indices = []
        for idx, line in enumerate(block):
            match = _call_match(line.strip())
            if not match:
                continue
            called_name = match.group(2)
            if called_name in {"require", "assert", "satisfy"}:
                continue
            if method_names and called_name not in method_names:
                continue
            call_indices.append((idx, match))

        if not call_indices or any(match.group(2) == expected_name for _, match in call_indices):
            novas.extend(block)
            i = j
            continue

        withrevert_calls = [(idx, match) for idx, match in call_indices if match.group(3)]
        target_idx, target_match = (withrevert_calls or call_indices)[-1]
        withrevert = bool(target_match.group(3))
        declarations, target_call = _build_target_call(
            expected_name,
            expected_params,
            block,
            withrevert,
            context.get("type", ""),
        )

        updated = []
        for idx, line in enumerate(block):
            if idx == target_idx:
                updated.extend(declarations)
                updated.append(target_call)
            else:
                updated.append(line)

        correcoes.append(
            f"{vuln_id or rule_name}: chamada alvo ajustada para {expected_name}()"
        )
        novas.extend(updated)
        i = j

    return '\n'.join(novas), correcoes


def aplicar_auth_probe_rules(spec_cvl: str, auth_probe: dict | None) -> tuple[str, list[str]]:
    """Rewrite tx-origin/auth rules to call a real onlyOwner function."""
    if not auth_probe or not auth_probe.get("name"):
        return spec_cvl, []

    linhas = spec_cvl.split('\n')
    novas = []
    correcoes = []
    previous_comment = ""
    in_auth_rule = False
    rule_name = ""
    depth = 0

    for linha in linhas:
        stripped = linha.strip()
        if stripped.startswith("//"):
            previous_comment = stripped

        rule_match = re.match(r'\s*rule\s+(\w+)', linha)
        if rule_match:
            rule_name = rule_match.group(1)
            is_auth_rule = _is_auth_rule(rule_name, previous_comment)
            if is_auth_rule:
                declarations, call = _auth_probe_declarations_and_call(auth_probe)
                novas.append(linha)
                novas.append("  env e;")
                novas.append("  require e.msg.sender != owner();")
                novas.extend(declarations)
                novas.append(call)
                novas.append("  assert lastReverted;")
                in_auth_rule = True
                depth = linha.count('{') - linha.count('}')
                correcoes.append(f"Rule '{rule_name}': auth probe ajustado para {auth_probe['name']}()")
                continue

        if in_auth_rule:
            depth += linha.count('{') - linha.count('}')
            if depth <= 0:
                novas.append(linha)
                in_auth_rule = False
                rule_name = ""
                depth = 0
            continue

        novas.append(linha)

    return '\n'.join(novas), correcoes


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
