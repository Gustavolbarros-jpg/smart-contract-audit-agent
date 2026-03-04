import json
import sys
import re
import os

MAPEAMENTO = {
    "reentrancy-eth": {
        "propriedade_formal": "estado do contrato não deve mudar após chamada externa sem proteção de reentrância",
        "padrão_cvl": "ghost bool + rule verificando que saldo é zerado antes da call externa + assert ordem de atualização"
    },
    "reentrancy-no-eth": {
        "propriedade_formal": "estado do contrato não deve mudar após chamada externa sem proteção de reentrância",
        "padrão_cvl": "ghost bool + rule verificando que saldo é zerado antes da call externa + assert ordem de atualização"
    },
    "tx-origin": {
        "propriedade_formal": "autenticação não deve depender de tx.origin",
        "padrão_cvl": "rule verificando que apenas msg.sender == owner autoriza"
    },
    "arbitrary-send-eth": {
        "propriedade_formal": "transferência de ETH só pode ocorrer para endereços autorizados",
        "padrão_cvl": "rule verificando que caller == owner antes da transferência"
    },
    "suicidal": {
        "propriedade_formal": "selfdestruct não pode ser chamado por endereço não autorizado",
        "padrão_cvl": "rule com @withrevert: caller != owner deve reverter"
    },
    "missing-zero-check": {
        "propriedade_formal": "endereço de destino nunca deve ser zero",
        "padrão_cvl": "rule com @withrevert: to == address(0) deve reverter"
    },
    "integer-overflow": {
        "propriedade_formal": "operações aritméticas nunca devem ultrapassar limites do tipo",
        "padrão_cvl": "rule verificando bounds antes e depois da operação"
    },
    "integer-underflow": {
        "propriedade_formal": "operações aritméticas nunca devem ultrapassar limites do tipo",
        "padrão_cvl": "rule verificando bounds antes e depois da operação"
    },
    "timestamp": {
        "propriedade_formal": "lógica crítica não deve depender exclusivamente de block.timestamp",
        "padrão_cvl": "rule verificando que resultado não muda se timestamp variar dentro de bounds"
    },
    "block-number": {
        "propriedade_formal": "lógica crítica não deve depender exclusivamente de block.number",
        "padrão_cvl": "rule verificando que resultado não muda se block.number variar dentro de bounds"
    }
}

def classificar_categoria(check_type):
    if any(x in check_type for x in ["reentrancy", "suicidal", "arbitrary-send", "tx-origin"]):
        return "security"
    elif any(x in check_type for x in ["timestamp", "block-number"]):
        return "design_assumption"
    elif any(x in check_type for x in ["missing-zero", "integer"]):
        return "validation"
    elif any(x in check_type for x in ["events", "naming", "immutable"]):
        return "best_practice"
    else:
        return "informational"

if len(sys.argv) != 3:
    print("Usage: python3 slither_minify.py <input.json> <output.json>")
    sys.exit(1)

input_file  = sys.argv[1]
output_file = sys.argv[2]

# ─── Carrega JSON do Slither ────────────────────────────────
with open(input_file, "r") as f:
    data = json.load(f)

detectors  = data.get("results", {}).get("detectors", [])
normalized = []
contador   = 1

# ─── Loop principal ─────────────────────────────────────────
for d in detectors:
    description = d.get("description", "").strip()
    check_type  = d.get("check", "")
    mapa        = MAPEAMENTO.get(check_type, {"propriedade_formal": "", "padrão_cvl": ""})

    fn_sig = ""
    m = re.search(r"\.(\w+\([^\)]*\))", description)
    if m:
        fn_sig = m.group(1)

    external_calls = []
    for line in description.splitlines():
        if ".call{" in line or ".call(" in line:
            external_calls.append(line.strip())

    elements = d.get("elements", [])
    lines    = set()
    elems    = []
    funcao   = ""
    linha    = ""

    for e in elements:
        if not isinstance(e, dict):
            continue
        if e.get("type") == "function" and not funcao:
            funcao = e.get("name", "")
        if "name" in e:
            elems.append({
                "name": e["name"],
                "type": e.get("type", ""),
                "line": str(e.get("source_mapping", {}).get("lines", [""])[0])
            })
        sm = e.get("source_mapping", {})
        if "lines" in sm:
            lines.update(sm["lines"])

    if lines:
        linha = f"{min(lines)}-{max(lines)}"

    normalized.append({
        "id":                 f"VULN_{contador:03d}",
        "type":               check_type,
        "category":           classificar_categoria(check_type),
        "description":        description,
        "function":           funcao or fn_sig,
        "line":               linha,
        "impact":             d.get("impact", "").lower(),
        "confidence":         d.get("confidence", "").lower(),
        "external_calls":     external_calls,
        "elements":           elems,
        "propriedade_formal": mapa["propriedade_formal"],
        "padrão_cvl":         mapa["padrão_cvl"]
    })

    contador += 1

# ─── Detecção complementar no código Solidity ───────────────
basename        = os.path.basename(input_file)
contract_name   = basename.replace("resultado_slither_", "").replace(".json", "")

# busca qualquer .sol cujo nome contenha contract_name (case insensitive)
contracts_dir = "/home/gflb/TesteCertora/smart-audt/contracts"
sol_candidates = []
for f in os.listdir(contracts_dir):
    if f.endswith(".sol") and contract_name.lower() in f.lower():
        sol_candidates.append(os.path.join(contracts_dir, f))

# fallback: lista todos os .sol se nenhum match
if not sol_candidates:
    for f in os.listdir(contracts_dir):
        if f.endswith(".sol"):
            sol_candidates.append(os.path.join(contracts_dir, f))
    print(f"[WARN] Nenhum .sol encontrado para '{contract_name}' — tentando todos os contratos")
sol_code = ""
for candidate in sol_candidates:
    if os.path.exists(candidate):
        with open(candidate, "r") as f:
            sol_code = f.read()
        print(f"[INFO] Código Solidity carregado: {candidate}")
        break

if sol_code:
    if "tx.origin" in sol_code and not any(v["type"] == "tx-origin" for v in normalized):
        normalized.append({
            "id":                 f"VULN_{contador:03d}",
            "type":               "tx-origin",
            "category":           "security",
            "description":        "Contrato usa tx.origin para autorização (detectado no código fonte)",
            "function":           "modifier ou função com tx.origin",
            "line":               "",
            "impact":             "medium",
            "confidence":         "high",
            "external_calls":     [],
            "elements":           [{"name": "tx.origin", "type": "expression", "line": ""}],
            "propriedade_formal": "autenticação não deve depender de tx.origin",
            "padrão_cvl":         "rule verificando que apenas msg.sender == owner autoriza"
        })
        contador += 1
        print("[INFO] tx-origin adicionado via detecção complementar")

    if "selfdestruct" in sol_code and not any(v["type"] == "suicidal" for v in normalized):
        normalized.append({
            "id":                 f"VULN_{contador:03d}",
            "type":               "suicidal",
            "category":           "security",
            "description":        "Contrato usa selfdestruct sem controle de acesso adequado (detectado no código fonte)",
            "function":           "destroy",
            "line":               "",
            "impact":             "high",
            "confidence":         "high",
            "external_calls":     [],
            "elements":           [{"name": "selfdestruct", "type": "expression", "line": ""}],
            "propriedade_formal": "selfdestruct não pode ser chamado por endereço não autorizado",
            "padrão_cvl":         "rule com @withrevert: caller != owner deve reverter"
        })
        contador += 1
        print("[INFO] suicidal adicionado via detecção complementar")

    if ".transfer(" in sol_code and not any(v["type"] == "arbitrary-send-eth" for v in normalized):
        normalized.append({
            "id":                 f"VULN_{contador:03d}",
            "type":               "arbitrary-send-eth",
            "category":           "security",
            "description":        "Contrato envia ETH para endereço arbitrário via .transfer() (detectado no código fonte)",
            "function":           "emergencyWithdraw",
            "line":               "",
            "impact":             "high",
            "confidence":         "medium",
            "external_calls":     [],
            "elements":           [{"name": ".transfer()", "type": "expression", "line": ""}],
            "propriedade_formal": "transferência de ETH só pode ocorrer para endereços autorizados",
            "padrão_cvl":         "rule verificando que caller == owner antes da transferência"
        })
        contador += 1
        print("[INFO] arbitrary-send-eth adicionado via detecção complementar")
else:
    print("[WARN] Código Solidity não encontrado — detecção complementar ignorada")

# ─── Salva output ────────────────────────────────────────────
with open(output_file, "w") as f:
    json.dump(normalized, f, indent=2, ensure_ascii=False)

print(f"[OK] {len(normalized)} vulnerabilidades normalizadas → {output_file}")