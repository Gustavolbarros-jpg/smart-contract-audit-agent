"""
agent/tools/certora_cli.py
Ferramenta para executar a Verificação Formal via Certora Prover.

Duas entradas, uma única construção de linha de comando:

* ``run_certora``   — a verificação do pipeline, que envia o job para a nuvem.
* ``verify_locally`` — o oráculo local: ``--compilation_steps_only`` para antes de
  *enviar*, não antes de *verificar*, então o ``emv.jar`` roda aqui e imprime
  vereditos de regra reais, sem job remoto e sem gastar cota.
"""
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from core.certora_error_catalog import analyze_certora_errors
from core.import_context import certora_compiler_flags, packages_path, solc_remappings


LOCAL_ONLY_FLAG = "--compilation_steps_only"
VACUITY_SUFFIX = "-rule_not_vacuous"
# "Verified: <rule>" / "Violated: <rule>", the lines the verifier prints per rule. The
# results table says "Not violated" instead, which these two words would read backwards.
_VERDICT_RE = re.compile(r"^(Verified|Violated):[ \t]*(\S+)[ \t]*$", re.MULTILINE)
# Every certoraRun built by hand so far lost one of the arguments below, so there is
# exactly one place that writes them.
_DEFAULT_ALLOW_PATH = ".."


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


def certora_argv(
    contract_path: str,
    spec_path: str,
    contract_name: str,
    msg: str = "Agent Verification",
    local_only: bool = False,
    allow_path: str = _DEFAULT_ALLOW_PATH,
) -> list[str]:
    """A invocação que o pipeline e o oráculo compartilham.

    Cada detalhe aqui custou uma rodada perdida: sem ``--solc_allow_path`` o Prover
    recusa fontes fora dos diretórios permitidos; sem as flags de otimizador do Foundry
    um contrato que compila no próprio projeto morre de "Stack too deep"; e cada
    remapping precisa de seu próprio ``--packages``.
    """
    argv = [
        "certoraRun",
        f"{contract_path}:{contract_name}",
        "--verify",
        f"{contract_name}:{spec_path}",
        "--solc_allow_path", allow_path,
        "--msg", msg,
    ]
    if local_only:
        argv.append(LOCAL_ONLY_FLAG)
    argv.extend(certora_compiler_flags(contract_path))
    package_dir = packages_path(contract_path)
    if package_dir:
        argv.extend(["--packages_path", str(package_dir)])
    for remap in solc_remappings(contract_path):
        argv.extend(["--packages", remap])
    return argv


def local_prover_requested() -> bool:
    """``AUDIT_CERTORA_LOCAL=1`` roda o pipeline inteiro só no verificador local.

    O log local traz as mesmas linhas ``Verified:``/``Violated:`` que ``core/certora_parser``
    já lê, então o resto do pipeline não muda — só deixa de enviar job e de gastar cota. Para
    o número final do relatório, a nuvem continua sendo a referência: o verificador local não
    tem o splitting nem os tempos de lá.
    """
    return os.getenv("AUDIT_CERTORA_LOCAL", "").strip().lower() not in ("", "0", "false", "no")


def _prover_env() -> dict[str, str]:
    # Without a display the Prover skips opening FinalResults.html in the user's browser.
    return {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}


def _contract_name_for(contract_path: str, override: str | None) -> str:
    return override or os.path.basename(contract_path).split(".")[0]


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

    file_name = os.path.basename(contract_path).split('.')[0]
    contract_name = _contract_name_for(contract_path, contract_name_override)
    local_only = local_prover_requested()
    cmd = certora_argv(contract_path, spec_path, contract_name, local_only=local_only)

    try:
        print(f"🔬 [Certora] Iniciando Prover para {file_name} ({contract_name}) com {os.path.basename(spec_path)}...")
        if local_only:
            print("💻 AUDIT_CERTORA_LOCAL=1: só o verificador local, nenhum job na nuvem, nenhuma cota.")
        else:
            print("⏳ Isso pode demorar alguns minutos...")

        timeout = int(os.getenv("AUDIT_CERTORA_TIMEOUT", "600"))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_prover_env())

        return result.stdout + "\n" + result.stderr

    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Certora abortado: excedeu {timeout // 60} minutos (AUDIT_CERTORA_TIMEOUT).")
    except FileNotFoundError:
        raise RuntimeError("'certoraRun' não encontrado. Certora CLI está instalado?")


@dataclass(frozen=True)
class LocalVerdict:
    """O que o verificador local disse sobre um par (contrato, spec)."""

    status: str                               # verified | violated | error | timeout
    rules: dict[str, str] = field(default_factory=dict)   # regra -> verified | violated
    sanity: dict[str, str] = field(default_factory=dict)  # os -rule_not_vacuous, à parte
    detail: str = ""
    log: str = ""
    argv: list[str] = field(default_factory=list)

    @property
    def violated_rules(self) -> list[str]:
        return sorted(name for name, verdict in self.rules.items() if verdict == "violated")

    @property
    def vacuous_rules(self) -> list[str]:
        """Regras que passaram porque deixaram de ser alcançáveis.

        O Prover reporta ``<regra>-rule_not_vacuous`` **Violated** quando a regra É
        alcançável. Se esse sanity check vira Verified, a regra passou sem ser exercitada —
        é assim que um "reparo" que faz a função reverter sempre satisfaz a spec sem
        consertar nada, e é por isso que o veredito sozinho não basta.

        Regra de ``satisfy`` não entra nessa conta, e não precisa: o Prover a reporta como
        ``<regra>-Satisfy_<assert>_(<arquivo>_<linha>_<coluna>)``, que nunca casa com o
        ``<regra>-rule_not_vacuous`` do sanity. Também não faria sentido -- uma regra de
        ``satisfy`` só passa exibindo uma execução testemunha, então passar *é* ser
        alcançável. Inalcançável nela aparece como Violated, não como passagem vácua.
        """
        return sorted(
            name for name, verdict in self.rules.items()
            if verdict == "verified" and self.sanity.get(name + VACUITY_SUFFIX) == "verified"
        )

    @property
    def conclusive(self) -> bool:
        """Só um veredito de regra distingue original de mutante; erro e timeout não."""
        return self.status in ("verified", "violated")


def parse_local_verdict(output: str, argv: list[str] | None = None) -> LocalVerdict:
    """Lê os vereditos de regra do log do Prover.

    ``<rule>-rule_not_vacuous`` fica separado: ele aparece Violated sempre que a regra é
    alcançável — é o sanity check que o CLAUDE.md manda ignorar — e decidiria o status ao
    contrário se entrasse na conta.
    """
    text = output or ""
    rules: dict[str, str] = {}
    sanity: dict[str, str] = {}
    for verdict, rule in _VERDICT_RE.findall(text):
        target = sanity if rule.endswith(VACUITY_SUFFIX) else rules
        target[rule] = verdict.lower()

    if not rules:
        matches = analyze_certora_errors(text)["matches"]
        detail = "; ".join(f"{item['id']}: {item['cause']}" for item in matches)
        return LocalVerdict(
            status="error",
            sanity=sanity,
            detail=detail or "nenhum veredito de regra no log do Prover",
            log=text,
            argv=list(argv or []),
        )

    violated = sorted(name for name, verdict in rules.items() if verdict == "violated")
    return LocalVerdict(
        status="violated" if violated else "verified",
        rules=rules,
        sanity=sanity,
        detail=", ".join(violated),
        log=text,
        argv=list(argv or []),
    )


def verify_locally(
    contract_path: str,
    spec_path: str,
    contract_name: str | None = None,
    timeout: int | None = None,
    log_path: str | None = None,
    cwd: str | None = None,
    allow_path: str = _DEFAULT_ALLOW_PATH,
    msg: str = "local oracle",
) -> LocalVerdict:
    """Verifica um par (contrato, spec) só com o verificador local: sem nuvem, sem cota.

    ``--compilation_steps_only`` para antes de *enviar* o job, não antes de *verificar*:
    o ``emv.jar`` roda aqui e imprime ``Verified:``/``Violated:`` de verdade. É isso que
    dá um oráculo de graça para mutantes que o stack estático não enxerga — AOR, BOR,
    UOR, EED e PKR têm detectabilidade medida zero no Slither.

    O log vai sempre para arquivo, nunca só para a memória: com ``capture_output`` um
    timeout descarta tudo que o Prover já havia impresso.
    """
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contrato não encontrado: {contract_path}")
    if not os.path.exists(spec_path):
        raise FileNotFoundError(f"Spec CVL não encontrado: {spec_path}")

    safe_copy = _certora_safe_copy(contract_path)
    if safe_copy:
        try:
            return verify_locally(
                safe_copy, spec_path, contract_name, timeout, log_path, cwd, allow_path, msg
            )
        finally:
            os.unlink(safe_copy)

    argv = certora_argv(
        contract_path,
        spec_path,
        _contract_name_for(contract_path, contract_name),
        msg=msg,
        local_only=True,
        allow_path=allow_path,
    )
    seconds = int(os.getenv("AUDIT_ORACLE_TIMEOUT", "300")) if timeout is None else timeout

    if log_path:
        # A pasta do log pode não existir ainda: o chamador escolhe o nome, não a árvore.
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    handle, temporary = (log_path, False) if log_path else (
        tempfile.mkstemp(prefix="certora_oracle_", suffix=".log")[1], True
    )
    try:
        with open(handle, "w", encoding="utf-8") as sink:
            try:
                subprocess.run(
                    argv, stdout=sink, stderr=subprocess.STDOUT, timeout=seconds,
                    env=_prover_env(), cwd=cwd, check=False,
                )
            except subprocess.TimeoutExpired:
                sink.flush()
                partial = _read(handle)
                return LocalVerdict(
                    status="timeout",
                    detail=f"excedeu {seconds}s (AUDIT_ORACLE_TIMEOUT)",
                    log=partial,
                    argv=argv,
                )
            except FileNotFoundError:
                raise RuntimeError("'certoraRun' não encontrado. Certora CLI está instalado?")
        return parse_local_verdict(_read(handle), argv)
    finally:
        if temporary:
            os.unlink(handle)


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return ""
