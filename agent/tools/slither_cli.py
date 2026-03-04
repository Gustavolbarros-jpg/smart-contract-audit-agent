"""
agent/tools/slither_cli.py
Ferramenta para executar o Slither e extrair apenas as vulnerabilidades minificadas.
"""
import subprocess
import json
import os
import re

# O seu mapeamento genial de regras formais
MAPEAMENTO = {
    "reentrancy-eth": {"propriedade_formal": "estado do contrato não deve mudar após chamada externa sem proteção de reentrância", "padrão_cvl": "ghost bool + rule verificando que saldo é zerado antes da call externa + assert ordem de atualização"},
    "reentrancy-no-eth": {"propriedade_formal": "estado do contrato não deve mudar após chamada externa sem proteção de reentrância", "padrão_cvl": "ghost bool + rule verificando que saldo é zerado antes da call externa + assert ordem de atualização"},
    "tx-origin": {"propriedade_formal": "autenticação não deve depender de tx.origin", "padrão_cvl": "rule verificando que apenas msg.sender == owner autoriza"},
    "arbitrary-send-eth": {"propriedade_formal": "transferência de ETH só pode ocorrer para endereços autorizados", "padrão_cvl": "rule verificando que caller == owner antes da transferência"},
    "suicidal": {"propriedade_formal": "selfdestruct não pode ser chamado por endereço não autorizado", "padrão_cvl": "rule com @withrevert: caller != owner deve reverter"},
    "missing-zero-check": {"propriedade_formal": "endereço de destino nunca deve ser zero", "padrão_cvl": "rule com @withrevert: to == address(0) deve reverter"},
    "integer-overflow": {"propriedade_formal": "operações aritméticas nunca devem ultrapassar limites do tipo", "padrão_cvl": "rule verificando bounds antes e depois da operação"},
    "integer-underflow": {"propriedade_formal": "operações aritméticas nunca devem ultrapassar limites do tipo", "padrão_cvl": "rule verificando bounds antes e depois da operação"},
    "timestamp": {"propriedade_formal": "lógica crítica não deve depender exclusivamente de block.timestamp", "padrão_cvl": "rule verificando que resultado não muda se timestamp variar dentro de bounds"},
    "block-number": {"propriedade_formal": "lógica crítica não deve depender exclusivamente de block.number", "padrão_cvl": "rule verificando que resultado não muda se block.number variar dentro de bounds"}
}

def classificar_categoria(check_type):
    if any(x in check_type for x in ["reentrancy", "suicidal", "arbitrary-send", "tx-origin"]): return "security"
    elif any(x in check_type for x in ["timestamp", "block-number"]): return "design_assumption"
    elif any(x in check_type for x in ["missing-zero", "integer"]): return "validation"
    elif any(x in check_type for x in ["events", "naming", "immutable"]): return "best_practice"
    else: return "informational"

def minificar_resultados(slither_json: dict, contract_path: str) -> list:
    """Filtra o JSON gigante do Slither e adiciona detecções manuais do código."""
    detectors = slither_json.get("results", {}).get("detectors", [])
    normalized = []
    contador = 1

    for d in detectors:
        check_type = d.get("check", "")
        # Ignoramos avisos informacionais que gastam tokens à toa
        if classificar_categoria(check_type) in ["informational", "best_practice"]:
            continue

        description = d.get("description", "").strip()
        mapa = MAPEAMENTO.get(check_type, {"propriedade_formal": "", "padrão_cvl": ""})
        
        funcao = ""
        elems = []
        for e in d.get("elements", []):
            if isinstance(e, dict):
                if e.get("type") == "function" and not funcao:
                    funcao = e.get("name", "")
                if "name" in e:
                    elems.append({"name": e["name"], "type": e.get("type", ""), "line": str(e.get("source_mapping", {}).get("lines", [""])[0])})

        normalized.append({
            "id": f"VULN_{contador:03d}",
            "type": check_type,
            "function": funcao,
            "description": description[:200] + "...", # Truncamos a descrição para poupar tokens
            "impact": d.get("impact", "").lower(),
            "confidence": d.get("confidence", "").lower(),
            "elements": elems[:3], # Pegamos no máximo 3 elementos para não explodir o JSON
            "propriedade_formal": mapa["propriedade_formal"],
            "padrão_cvl": mapa["padrão_cvl"]
        })
        contador += 1

    # Busca no código fonte (fallback inteligente)
    if os.path.exists(contract_path):
        with open(contract_path, "r", encoding="utf-8") as f:
            sol_code = f.read()
            if "tx.origin" in sol_code and not any(v["type"] == "tx-origin" for v in normalized):
                normalized.append({"id": f"VULN_{contador:03d}", "type": "tx-origin", "function": "modifier/function", "description": "Contrato usa tx.origin", "impact": "medium", "confidence": "high", "elements": [], "propriedade_formal": MAPEAMENTO["tx-origin"]["propriedade_formal"], "padrão_cvl": MAPEAMENTO["tx-origin"]["padrão_cvl"]})
                contador += 1
            if "selfdestruct" in sol_code and not any(v["type"] == "suicidal" for v in normalized):
                normalized.append({"id": f"VULN_{contador:03d}", "type": "suicidal", "function": "destroy", "description": "Contrato usa selfdestruct", "impact": "high", "confidence": "high", "elements": [], "propriedade_formal": MAPEAMENTO["suicidal"]["propriedade_formal"], "padrão_cvl": MAPEAMENTO["suicidal"]["padrão_cvl"]})

    return normalized

def run_slither(contract_path: str) -> list:
    """Roda o Slither e retorna diretamente a lista minificada."""
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contrato não encontrado: {contract_path}")
    
    cmd = ["slither", contract_path, "--json", "-", "--no-fail-pedantic"]
    
    try:
        print(f"🔧 [Slither] Analisando {contract_path}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.stdout.strip():
            json_bruto = json.loads(result.stdout.strip())
            # A MÁGICA ACONTECE AQUI: Minificamos antes de devolver!
            return minificar_resultados(json_bruto, contract_path)
        else:
            return []
            
    except subprocess.TimeoutExpired:
        raise TimeoutError("Slither demorou mais de 2 minutos.")
    except json.JSONDecodeError:
        raise ValueError("Slither não retornou um JSON válido.")