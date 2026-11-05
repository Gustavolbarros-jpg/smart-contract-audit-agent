"""
agent/tools/certora_cli.py
Ferramenta para executar a Verificação Formal via Certora Prover.
"""
import os
import re
import shutil
import subprocess

from core.import_context import certora_compiler_flags, packages_path, solc_remappings


def _certora_safe_copy(contract_path: str) -> str | None:
    """The Prover rejects file names with characters such as '-' ("files must end with one
    of these extensions"). Return a sanitized copy beside the original (relative imports
    keep resolving), or None when the name is already acceptable."""
    directory, name = os.path.split(contract_path)
    safe = re.sub(r"[^A-Za-z0-9_.]", "_", name)
    if safe == name:
        return None
    copy = os.path.join(directory, f"_certora_{safe}")
    shutil.copyfile(contract_path, copy)
    return copy


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

    safe_copy = _certora_safe_copy(contract_path)
    if safe_copy:
        try:
            return run_certora(safe_copy, spec_path, output_dir, contract_name_override)
        finally:
            os.unlink(safe_copy)

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
    cmd.extend(certora_compiler_flags(contract_path))
    package_dir = packages_path(contract_path)
    if package_dir:
        cmd.extend(["--packages_path", str(package_dir)])
    for remap in solc_remappings(contract_path):
        cmd.extend(["--packages", remap])

    try:
        print(f"🔬 [Certora] Iniciando Prover para {file_name} ({contract_name}) com {os.path.basename(spec_path)}...")
        print("⏳ Isso pode demorar alguns minutos...")

        timeout = int(os.getenv("AUDIT_CERTORA_TIMEOUT", "600"))
        # Without a display the Prover skips opening FinalResults.html in the user's browser.
        env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)

        return result.stdout + "\n" + result.stderr

    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Certora abortado: excedeu {timeout // 60} minutos (AUDIT_CERTORA_TIMEOUT).")
    except FileNotFoundError:
        raise RuntimeError("'certoraRun' não encontrado. Certora CLI está instalado?")
