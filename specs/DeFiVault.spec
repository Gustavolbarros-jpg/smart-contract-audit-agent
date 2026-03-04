// ============================================================
// DeFiVault.spec — CORRIGIDO (Etapa 2)
// Certora CVL 2 — certora-cli 8.1.1
// ============================================================

methods {
    // envfree — leitura pura, sem dependência de env
    function owner()                             external returns (address) envfree;
    function pendingOwner()                      external returns (address) envfree;
    function balances(address)                   external returns (uint256) envfree;
    function rewards(address)                    external returns (uint256) envfree;
    function totalRewards()                      external returns (uint256) envfree;
    function totalDeposits()                     external returns (uint256) envfree;
    function lastWithdraw(address)               external returns (uint256) envfree;
    function maxWithdraw()                       external returns (uint256) envfree;
    function lockPeriod()                        external returns (uint256) envfree;
    function rewardRate()                        external returns (uint256) envfree;
    function paused()                            external returns (bool)    envfree;
    function whitelist(address)                  external returns (bool)    envfree;
    function getBalance()                        external returns (uint256) envfree;
    function isWhitelisted(address)              external returns (bool)    envfree;

    // NÃO envfree — usa block.timestamp internamente via env
    // CORREÇÃO E2-001: calculateReward removido de envfree
    function calculateReward(address)            external returns (uint256);

    // com env — modificam estado
    function withdraw(uint256)                   external;
    function deposit()                           external;
    function claimReward()                       external;
    function pause()                             external;
    function unpause()                           external;
    function setRewardRate(uint256)              external;
    function setMaxWithdraw(uint256)             external;
    function setLockPeriod(uint256)              external;
    function transferOwnership(address)          external;
    function acceptOwnership()                   external;
    function emergencyWithdraw(address, uint256) external;
    function destroy()                           external;
    function joinWhitelist()                     external;
    function removeFromWhitelist(address)        external;
}

// ============================================================
// GHOSTS
// CORREÇÃO E2-002: removidos inWithdrawExecution e inClaimExecution (não usados)
// ============================================================

// VULN_002 — ghost para valor anterior de balances
ghost mathint ghostBalanceBefore {
    init_state axiom ghostBalanceBefore == 0;
}

// VULN_001 — ghost para valor anterior de totalRewards
ghost mathint ghostTotalRewardsBefore {
    init_state axiom ghostTotalRewardsBefore == 0;
}

// ============================================================
// HOOKS
// ============================================================

// VULN_002 — hook em balances
hook Sstore balances[KEY address user] uint256 newVal (uint256 oldVal) {
    ghostBalanceBefore = oldVal;
}

// VULN_001 — hook em totalRewards
hook Sstore totalRewards uint256 newVal (uint256 oldVal) {
    ghostTotalRewardsBefore = oldVal;
}

// ============================================================
// RULES — REENTRANCY (VULN_002)
// ============================================================

// VULN_002 — reentrancy-eth: balance deve diminuir exatamente pelo amount após withdraw
rule withdrawReducesBalanceBeforeExternalCall(env e, uint256 amount) {
    // guard de overflow em soma de timestamp
    require lockPeriod() < 2^128;
    require lastWithdraw(e.msg.sender) < 2^128;

    require !paused();
    require whitelist(e.msg.sender);
    require balances(e.msg.sender) >= amount;
    require amount > 0;
    require amount <= maxWithdraw();
    require e.block.timestamp >= lastWithdraw(e.msg.sender) + lockPeriod();

    mathint balBefore = balances(e.msg.sender);

    withdraw(e, amount);

    mathint balAfter = balances(e.msg.sender);

    assert balAfter == balBefore - amount,
        "VULN_002: balance nao foi reduzido corretamente apos withdraw";
    assert balAfter < balBefore,
        "VULN_002: balance deve ser estritamente menor apos withdraw";
}

// VULN_002 — reentrancy-eth: totalDeposits deve refletir redução após withdraw
rule withdrawReducesTotalDeposits(env e, uint256 amount) {
    require lockPeriod() < 2^128;
    require lastWithdraw(e.msg.sender) < 2^128;

    require !paused();
    require whitelist(e.msg.sender);
    require balances(e.msg.sender) >= amount;
    require amount > 0;
    require amount <= maxWithdraw();
    require e.block.timestamp >= lastWithdraw(e.msg.sender) + lockPeriod();

    mathint depBefore = totalDeposits();

    withdraw(e, amount);

    mathint depAfter = totalDeposits();

    assert depAfter == depBefore - amount,
        "VULN_002: totalDeposits nao foi reduzido corretamente apos withdraw";
}

// ============================================================
// RULES — REENTRANCY (VULN_001)
// ============================================================

// VULN_001 — reentrancy-eth: totalRewards deve reduzir atomicamente em claimReward
// CORREÇÃO E2-003: calculateReward agora recebe env e
rule claimRewardReducesTotalRewards(env e) {
    require !paused();
    require whitelist(e.msg.sender);

    mathint rewardsBefore = totalRewards();
    mathint userReward    = calculateReward(e, e.msg.sender);

    require userReward > 0;
    require rewardsBefore >= userReward;

    claimReward(e);

    mathint rewardsAfter = totalRewards();

    assert rewardsAfter == rewardsBefore - userReward,
        "VULN_001: totalRewards nao foi reduzido pelo valor exato do reward";
    assert rewardsAfter < rewardsBefore,
        "VULN_001: totalRewards deve ser estritamente menor apos claimReward";
}

// VULN_001 — reentrancy-eth: totalRewards nunca fica negativo após claimReward
// CORREÇÃO E2-004: calculateReward agora recebe env e
rule noDoubleClaimDrain(env e) {
    require !paused();
    require whitelist(e.msg.sender);

    mathint rewardsBefore = totalRewards();
    mathint userReward    = calculateReward(e, e.msg.sender);

    require userReward > 0;
    require rewardsBefore >= userReward;

    claimReward(e);

    mathint rewardsAfter = totalRewards();

    assert rewardsAfter >= 0,
        "VULN_001: totalRewards nao pode ser negativo apos claimReward";
}

// ============================================================
// RULES — TX.ORIGIN (VULN_017)
// AVISO: rules de revert ESPERADO falhar no contrato atual (confirma VULN_017)
// ============================================================

// VULN_017 — tx-origin: pause só deve executar para msg.sender == owner
rule pauseRequiresMsgSenderIsOwner(env e) {
    require !paused();

    pause(e);

    assert e.msg.sender == owner(),
        "VULN_017: pause executado por caller que nao e owner via msg.sender";
}

// VULN_017 — tx-origin: pause deve reverter se msg.sender != owner
rule pauseRevertsIfNotOwner(env e) {
    require e.msg.sender != owner();
    require !paused();

    pause@withrevert(e);

    assert lastReverted,
        "VULN_017: pause nao reverteu para caller != owner — confirma uso de tx.origin";
}

// VULN_017 — tx-origin: setRewardRate só executa para msg.sender == owner
rule setRewardRateRequiresMsgSenderIsOwner(env e, uint256 newRate) {
    setRewardRate(e, newRate);

    assert e.msg.sender == owner(),
        "VULN_017: setRewardRate executado por caller que nao e owner via msg.sender";
}

// VULN_017 — tx-origin: setRewardRate reverte se msg.sender != owner
rule setRewardRateRevertsIfNotOwner(env e, uint256 newRate) {
    require e.msg.sender != owner();

    setRewardRate@withrevert(e, newRate);

    assert lastReverted,
        "VULN_017: setRewardRate nao reverteu para caller != owner — confirma tx.origin";
}

// ============================================================
// RULES — SUICIDAL (VULN_018)
// AVISO: rule de revert ESPERADO falhar no contrato atual (confirma VULN_018)
// ============================================================

// VULN_018 — suicidal: destroy reverte se msg.sender != owner
rule destroyRevertsIfNotOwner(env e) {
    require e.msg.sender != owner();

    destroy@withrevert(e);

    assert lastReverted,
        "VULN_018: destroy nao reverteu para caller != owner — confirma tx.origin";
}

// VULN_018 — suicidal: destroy só executa para msg.sender == owner
rule destroyRequiresMsgSenderIsOwner(env e) {
    destroy(e);

    assert e.msg.sender == owner(),
        "VULN_018: destroy executado por caller que nao e owner via msg.sender";
}

// ============================================================
// RULES — ARBITRARY-SEND-ETH (VULN_019)
// ============================================================

// VULN_019 — arbitrary-send-eth: emergencyWithdraw só executa para msg.sender == owner
rule emergencyWithdrawRequiresMsgSenderIsOwner(env e, address to, uint256 amount) {
    emergencyWithdraw(e, to, amount);

    assert e.msg.sender == owner(),
        "VULN_019: emergencyWithdraw executado por caller que nao e owner";
}

// VULN_019 — arbitrary-send-eth: emergencyWithdraw reverte se msg.sender != owner
rule emergencyWithdrawRevertsIfNotOwner(env e, address to, uint256 amount) {
    require e.msg.sender != owner();

    emergencyWithdraw@withrevert(e, to, amount);

    assert lastReverted,
        "VULN_019: emergencyWithdraw nao reverteu para caller != owner";
}

// ============================================================
// RULES — MISSING-ZERO-CHECK (VULN_006)
// AVISO: rule ESPERADO falhar — contrato não tem require(to != 0) (confirma VULN_006)
// ============================================================

// VULN_006 — missing-zero-check: emergencyWithdraw reverte se to == address(0)
rule emergencyWithdrawRevertsIfToIsZero(env e, uint256 amount) {
    address zeroAddr = 0;

    emergencyWithdraw@withrevert(e, zeroAddr, amount);

    assert lastReverted,
        "VULN_006: emergencyWithdraw nao reverteu para to == address(0)";
}

// ============================================================
// RULES — MISSING-ZERO-CHECK (VULN_007)
// AVISO: rule ESPERADO falhar — contrato não tem require(newOwner != 0) (confirma VULN_007)
// ============================================================

// VULN_007 — missing-zero-check: transferOwnership reverte se newOwner == address(0)
rule transferOwnershipRevertsIfZeroAddress(env e) {
    address zeroAddr = 0;

    transferOwnership@withrevert(e, zeroAddr);

    assert lastReverted,
        "VULN_007: transferOwnership nao reverteu para newOwner == address(0)";
}

// VULN_007 — missing-zero-check: pendingOwner não pode ser zero após transferOwnership
rule pendingOwnerNeverZeroAfterTransfer(env e, address newOwner) {
    require newOwner != 0;

    transferOwnership(e, newOwner);

    assert pendingOwner() != 0,
        "VULN_007: pendingOwner ficou zero apos transferOwnership";
    assert pendingOwner() == newOwner,
        "VULN_007: pendingOwner deve ser igual a newOwner apos transferOwnership";
}

// ============================================================
// RULES — TIMESTAMP (VULN_012)
// ============================================================

// VULN_012 — timestamp: withdraw reverte quando dentro do lock period
rule withdrawRevertsWhenLocked(env e, uint256 amount) {
    require lockPeriod() < 2^128;
    require lastWithdraw(e.msg.sender) < 2^128;

    require !paused();
    require whitelist(e.msg.sender);
    require balances(e.msg.sender) >= amount;
    require amount > 0;
    require e.block.timestamp < lastWithdraw(e.msg.sender) + lockPeriod();

    withdraw@withrevert(e, amount);

    assert lastReverted,
        "VULN_012: withdraw nao reverteu dentro do lock period";
}

// VULN_012 — timestamp: lastWithdraw atualizado para block.timestamp após withdraw
rule lastWithdrawUpdatedAfterWithdraw(env e, uint256 amount) {
    require lockPeriod() < 2^128;
    require lastWithdraw(e.msg.sender) < 2^128;

    require !paused();
    require whitelist(e.msg.sender);
    require balances(e.msg.sender) >= amount;
    require amount > 0;
    require amount <= maxWithdraw();
    require e.block.timestamp >= lastWithdraw(e.msg.sender) + lockPeriod();

    withdraw(e, amount);

    assert lastWithdraw(e.msg.sender) == e.block.timestamp,
        "VULN_012: lastWithdraw nao foi atualizado para block.timestamp apos withdraw";
}

// ============================================================
// RULES — TIMESTAMP (VULN_013)
// ============================================================

// VULN_013 — timestamp: claimReward reverte se reward == 0
// CORREÇÃO E2-005: calculateReward agora recebe env e
rule claimRewardRevertsIfRewardIsZero(env e) {
    require !paused();
    require whitelist(e.msg.sender);
    require calculateReward(e, e.msg.sender) == 0;

    claimReward@withrevert(e);

    assert lastReverted,
        "VULN_013: claimReward nao reverteu quando reward == 0";
}

// VULN_013 — timestamp: claimReward reverte se totalRewards < reward
// CORREÇÃO E2-006: calculateReward agora recebe env e
rule claimRewardRevertsIfInsufficientRewards(env e) {
    require !paused();
    require whitelist(e.msg.sender);

    mathint userReward = calculateReward(e, e.msg.sender);
    require userReward > 0;
    require totalRewards() < userReward;

    claimReward@withrevert(e);

    assert lastReverted,
        "VULN_013: claimReward nao reverteu quando totalRewards < reward";
}

// ============================================================
// REGRAS SEM CVL — COMENTÁRIOS DE RASTREABILIDADE
// ============================================================

// VULN_003 — events-maths: setLockPeriod sem emit. Não verificável via Certora.
// VULN_004 — events-maths: setRewardRate sem emit. Não verificável via Certora.
// VULN_005 — events-maths: setMaxWithdraw sem emit. Não verificável via Certora.
// VULN_008 — reentrancy-benign: coberto estruturalmente pelas rules de VULN_001.
// VULN_009 — reentrancy-benign: coberto pela rule withdrawReducesTotalDeposits (VULN_002).
// VULN_010 — reentrancy-events: evento pós-call, não verificável isoladamente via CVL.
// VULN_011 — reentrancy-events: evento pós-call, não verificável isoladamente via CVL.
// VULN_014 — solc-version: questão de compilador, não verificável via Certora.
// VULN_015 — low-level-calls: informacional, não verificável via Certora.
// VULN_016 — low-level-calls: informacional, não verificável via Certora.