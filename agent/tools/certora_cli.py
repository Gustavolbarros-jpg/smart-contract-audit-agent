"""
agent/tools/certora_cli.py
Ferramenta para executar a Verificação Formal via Certora Prover.
"""
import subprocess
import os


def run_certora(
    contract_path: str,
    spec_path: str,
    output_dir: str,
    contract_name_override: str = None
) -> str:
    """
    Roda o Certora Prover e retorna o output bruto (stdout + stderr).

    contract_path: caminho REAL do arquivo .sol (pode ser agent_outputs/ ou smart-audt/contracts/)
    contract_name_override: nome do contrato DENTRO do arquivo .sol.
      Útil quando o arquivo se chama DeFiVault_FIXED.sol mas o contrato
      interno ainda se chama DeFiVault.
      Se não informado, usa o nome do arquivo como padrão.
    """
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contrato não encontrado: {contract_path}")
    if not os.path.exists(spec_path):
        raise FileNotFoundError(f"Spec CVL não encontrado: {spec_path}")

    # Usa o contract_path REAL passado pelo chamador
    file_name     = os.path.basename(contract_path).split('.')[0]
    contract_name = contract_name_override if contract_name_override else file_name

    cmd = [
        "certoraRun",
        f"{contract_path}:{contract_name}",   # ← usa o caminho real
        "--verify",
        f"{contract_name}:{spec_path}",
        "--solc_allow_path", "..",
        "--msg", "Agent Verification"
    ]

    try:
        print(f"🔬 [Certora] Iniciando Prover para {file_name} ({contract_name}) com {os.path.basename(spec_path)}...")
        print("⏳ Isso pode demorar alguns minutos...")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        return result.stdout + "\n" + result.stderr

    except subprocess.TimeoutExpired:
        raise TimeoutError("Certora abortado: excedeu 10 minutos.")
    except FileNotFoundError:
        raise RuntimeError("'certoraRun' não encontrado. Certora CLI está instalado?")