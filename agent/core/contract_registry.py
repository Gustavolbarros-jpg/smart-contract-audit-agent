"""Contract registry for separating benchmark targets from manual examples."""

from __future__ import annotations

from dataclasses import dataclass


BENCHMARK = "benchmark"
EXPLORATORY = "exploratory"
MANUAL = "manual"
SCRATCH = "scratch"


@dataclass(frozen=True)
class ContractEntry:
    name: str
    path: str
    group: str
    description: str


CONTRACT_REGISTRY = [
    ContractEntry(
        "SimpleBank",
        "smart-audt/contracts/SimpleBank.sol",
        BENCHMARK,
        "Core positive benchmark for missing-zero-check and tx-origin flows.",
    ),
    ContractEntry(
        "King",
        "smart-audt/contracts/King.sol",
        BENCHMARK,
        "Core positive benchmark for auth, arbitrary-send-eth, and zero-check flows.",
    ),
    ContractEntry(
        "CrowdfundingVault",
        "smart-audt/contracts/CrowdfundingVault.sol",
        BENCHMARK,
        "Core positive benchmark including static-confirmed unchecked-lowlevel.",
    ),
    ContractEntry(
        "DeFiVault",
        "smart-audt/contracts/DeFiVault.sol",
        BENCHMARK,
        "Core positive benchmark for mixed auth, zero-check, suicidal, and send flows.",
    ),
    ContractEntry(
        "ERC2771MulticallVulnerable",
        "smart-audt/contracts/ERC2771MulticallVulnerable.sol",
        BENCHMARK,
        "Core positive benchmark for ERC2771 plus delegatecall multicall composition.",
    ),
    ContractEntry(
        "TimelockVault",
        "smart-audt/contracts/TimelockVault.sol",
        EXPLORATORY,
        "Exploratory positive case for unprotected critical state updates.",
    ),
    ContractEntry(
        "AnotherVulnerableBank",
        "smart-audt/contracts/AnotherVulnerableBank.sol",
        EXPLORATORY,
        "Runnable Solidity 0.8 bank example; useful for exploratory Slither coverage.",
    ),
    ContractEntry(
        "VulnerableBankToken",
        "smart-audt/contracts/VulnerableBankToken.sol",
        EXPLORATORY,
        "Runnable negative/control benchmark currently producing no actionable candidates.",
    ),
    ContractEntry(
        "DeFiVault_FIXED",
        "smart-audt/contracts/DeFiVault_FIXED.sol",
        MANUAL,
        "Generated or corrected output; keep out of default benchmark inputs.",
    ),
    ContractEntry(
        "ERC2771MulticallVulnerable_FIXED",
        "smart-audt/contracts/ERC2771MulticallVulnerable_FIXED.sol",
        MANUAL,
        "Generated or corrected output; keep out of default benchmark inputs.",
    ),
    ContractEntry(
        "SimpleBank_FIXED",
        "smart-audt/contracts/SimpleBank_FIXED.sol",
        MANUAL,
        "Generated or corrected output; keep out of default benchmark inputs.",
    ),
    ContractEntry(
        "SafeBankToken",
        "smart-audt/contracts/SafeBankToken.sol",
        MANUAL,
        "Manual corrected example for bank-token experiments.",
    ),
    ContractEntry(
        "SafeBankToken2",
        "smart-audt/contracts/SafeBankToken2.sol",
        MANUAL,
        "Manual corrected example for bank-token experiments.",
    ),
    ContractEntry(
        "SuperSecureBank",
        "smart-audt/contracts/SuperSecureBank.sol",
        MANUAL,
        "Manual final/corrected bank example.",
    ),
    ContractEntry(
        "VulnerableBankTokenCorrected",
        "smart-audt/contracts/VulnerableBankTokenCorrected.sol",
        MANUAL,
        "Manual corrected bank-token example.",
    ),
    ContractEntry(
        "VulnerableVault",
        "smart-audt/contracts/VulnerableVault.sol",
        MANUAL,
        "Manual patched vault with embedded experiment notes.",
    ),
    ContractEntry(
        "TreasuryVault",
        "smart-audt/contracts/TreasuryVault.sol",
        SCRATCH,
        "Malformed scratch/example file; excluded from benchmark runs.",
    ),
]


def contract_groups() -> list[str]:
    return [BENCHMARK, EXPLORATORY, MANUAL, SCRATCH]


def contract_entries(group: str = "") -> list[ContractEntry]:
    if not group or group == "all":
        return list(CONTRACT_REGISTRY)
    return [entry for entry in CONTRACT_REGISTRY if entry.group == group]


def contract_names(group: str = "") -> list[str]:
    return [entry.name for entry in contract_entries(group)]


def default_benchmark_contracts(include_exploratory: bool = False) -> list[str]:
    names = contract_names(BENCHMARK)
    if include_exploratory:
        names.extend(contract_names(EXPLORATORY))
    return names
