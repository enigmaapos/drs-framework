drs-framework

Decentralized Recovery System (DRS) is a guardian-based security layer for smart contracts.
It provides a robust alternative to traditional multisig, timelock, or DAO-only approaches.

DRS enables:

Fast recovery from lost or compromised deployer/admin keys.

Guardian-based approval flow (e.g., 5-of-7, 4-of-7).

Automatic compromise detection (⚠️ warning at 6/7, 🚨 auto-lock at 7/7).

Reset and recovery mechanisms controlled by valid owners or last honest guardians.

Upgrade-safe and pluggable security, usable with any Solidity contract.



---

✨ Features

Guardian Council Security System (GCSS): Protects deployer addresses.

Admin Guardian Council (AGC): Protects DEFAULT_ADMIN_ROLE (upgrade/role manager).

Shared Guardian Council: Single council for both deployer and admin.

Batch Guardian Council (BGC): Dual-batch system for instant failover — if Batch 1 is compromised, Batch 2 automatically steps in.

Flexible Thresholds: Configurable council size (e.g., 5-of-7, 4-of-7).

Failsafe Locks: Auto-lock when full compromise is suspected.

Recovery Flow: Propose → Approve → Execute → Reset guardians if needed.



---

📚 Documentation

contracts/GuardianLib.sol — shared library.

contracts/examples/ — GCSS, AGC, and Shared council variants.

contracts/BatchGuardianCouncil.sol — new batch-based guardian system (DRS v2).

Integration Example: Catalyst Repo.



---

🚀 Getting Started

Clone the repo:

git clone https://github.com/enigmaapos/drs-framework.git
cd drs-framework

Install dependencies (if using Hardhat/Foundry):

npm install
# or
forge install

Compile contracts:

npx hardhat compile
# or
forge build

Run tests:

npx hardhat test
# or
forge test


---

🔄 Module Options

Module	Description	Use Case

GCSS	Guardian Council for deployer role	Protects deployer fee receiver
AGC	Guardian Council for admin role	Protects DEFAULT_ADMIN_ROLE upgrades
Shared	One council for both deployer/admin	Simpler deployments
Batch GC (BGC)	Two batches of guardians	Faster failover + extra resilience (DRS v2)



---

🆚 DRS Versions

DRS v1 (Classic) → GCSS / AGC / Shared councils. Lightweight, efficient, best for smaller projects.

DRS v2 (Batch GC) → Adds automatic failover with multiple batches. Best for protocols with large treasuries or long-term governance needs.



---

📜 License
This project is licensed under the MIT License.


---

💡 Note:
DRS is modular — projects can choose between Classic Councils (GCSS/AGC/Shared) or the Batch Guardian Council (BGC) depending on their risk profile and governance model.
