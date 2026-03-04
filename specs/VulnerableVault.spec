// ============================================================
// VulnerableVault.spec
// Gerado para: certora-cli 8.1.1 / CVL 2
// Baseado em: VULN_001 a VULN_009 (Etapa 1)
// ============================================================

using VulnerableVault as vault;

methods {
    function owner()                            external returns (address) envfree;
    function balances(address)                  external returns (uint256)  envfree;

    function deposit()                          external;
    function withdraw()                         external;
    function emergencyWithdraw(address)         external;
    function destroy()                          external;
}

// ============================================================
// GHOSTS — VULN_001 (reentrancy-eth)
// ============================================================

ghost bool inWithdrawExecution {
    init_state axiom inWithdrawExecution == false;
}

ghost mathint lastBalanceBefore {
    init_state axiom lastBalanceBefore == 0;
}

hook Sstore balances[KEY address user] uint256 newVal (uint256 oldVal) {
    lastBalanceBefore = oldVal;
}

// ============================================================
// RULES
// ============================================================

// VULN_001 — reentrancy-eth
rule withdraw_zeroes_balance_after_execution(address caller) {
    env e;
    require e.msg.sender == caller;
    require e.msg.value == 0;

    uint256 balBefore = balances(caller);
    require balBefore > 0;

    withdraw(e);

    uint256 balAfter = balances(caller);

    assert balAfter == 0,
        "VULN_001: saldo deve ser zero apos withdraw bem-sucedido";
    assert balAfter < balBefore,
        "VULN_001: saldo apos withdraw deve ser menor que antes";
}

// VULN_001 — reentrancy-eth
rule withdraw_cannot_increase_balance(address caller) {
    env e;
    require e.msg.sender == caller;
    require e.msg.value == 0;

    uint256 balBefore = balances(caller);

    withdraw(e);

    uint256 balAfter = balances(caller);

    assert balAfter <= balBefore,
        "VULN_001: withdraw nao pode aumentar o saldo do caller";
}

// VULN_002 — arbitrary-send-eth
rule emergencyWithdraw_only_owner_succeeds(address to) {
    env e;
    require e.msg.value == 0;

    emergencyWithdraw(e, to);

    assert e.msg.sender == owner(),
        "VULN_002: emergencyWithdraw executado sem ser o owner";
}

// VULN_002 — arbitrary-send-eth
rule emergencyWithdraw_reverts_if_not_owner(address to) {
    env e;
    require e.msg.value == 0;
    require e.msg.sender != owner();

    emergencyWithdraw@withrevert(e, to);

    assert lastReverted,
        "VULN_002: chamada de non-owner deveria reverter";
}

// VULN_003 — suicidal
rule destroy_reverts_if_not_owner() {
    env e;
    require e.msg.value == 0;
    require e.msg.sender != owner();

    destroy@withrevert(e);

    assert lastReverted,
        "VULN_003: destroy por non-owner deve reverter";
}

// VULN_004 — tx-origin (emergencyWithdraw)
rule emergencyWithdraw_auth_via_msg_sender(address to) {
    env e;
    require e.msg.value == 0;

    emergencyWithdraw(e, to);

    assert e.msg.sender == owner(),
        "VULN_004: autorizacao deve ser por msg.sender, nao tx.origin";
}

// VULN_004 — tx-origin (emergencyWithdraw)
rule emergencyWithdraw_reverts_when_sender_not_owner(address to) {
    env e;
    require e.msg.value == 0;
    require e.msg.sender != owner();

    emergencyWithdraw@withrevert(e, to);

    assert lastReverted,
        "VULN_004: msg.sender != owner deve reverter em emergencyWithdraw";
}

// VULN_005 — tx-origin (destroy)
rule destroy_auth_via_msg_sender() {
    env e;
    require e.msg.value == 0;

    destroy(e);

    assert e.msg.sender == owner(),
        "VULN_005: autorizacao de destroy deve ser por msg.sender";
}

// VULN_005 — tx-origin (destroy)
rule destroy_reverts_when_sender_not_owner() {
    env e;
    require e.msg.value == 0;
    require e.msg.sender != owner();

    destroy@withrevert(e);

    assert lastReverted,
        "VULN_005: msg.sender != owner deve reverter em destroy";
}

// VULN_006 — missing-zero-check
rule emergencyWithdraw_reverts_on_zero_address(address to) {
    env e;
    require e.msg.value == 0;
    require to == 0;

    emergencyWithdraw@withrevert(e, to);

    assert lastReverted,
        "VULN_006: to == address(0) deve causar revert em emergencyWithdraw";
}

// VULN_007 — solc-version
// Fora de escopo CVL: issue de compilador, nao verificavel por prova formal

// VULN_008 — low-level-calls
// Fora de escopo CVL: coberto estruturalmente por VULN_001

// VULN_009 — immutable-states
// Fora de escopo CVL: otimizacao de gas, sem impacto em propriedades logicas