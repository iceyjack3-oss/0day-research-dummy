# 0day-research-dummy

# 🚨 SECURITY ADVISORY: CRITICAL ENTRYPOINT DISPATCHER BYPASS
**Vulnerability Pattern:** Missing Account Owner Validation  
**CVE-Candidate:** No owner verification prior to account data parsing  

---

### 📌 TARGET ANALYSIS
* **Program ID:** `<TARGET_PROGRAM_ID>`  
* **Faulty Code Site:** Entrypoint Dispatcher (`<DISPATCH_ADDR>`)  
* **Note:** This research is published as an anonymized live 0-day architectural case study for educational and defensive purposes this proves that ai can surpass humans bug found in a single day & first time vuln hunting seriously, I don't know rust or ebpf. 

---

### 🔎 TECHNICAL ANALYSIS & DISASSEMBLY MAPPING

#### 🛠️ Function <ITER_FN> (<ITER_FN_ADDR>) — Account Data Window Iterator
* Iterates a fixed-length window of **26 bytes** into account data at `[r2+offset]` looking for string null terminators.
* **Missing Check:** No owner comparison loop exists anywhere in this subroutine. 
* It explicitly checks `ldxb r0, [r3]` for `0x00` and checks `ldxb r0, [r2+1]` / `[r2+2]` for terminator boundaries.
* Static error strings `"is not a signer"` (`<SIGNER_STR_ADDR>`) and `"is not writable"` (`<WRITABLE_STR_ADDR>`) are present in the text segment, but **no** `"is not owned by"` instruction block or validation routine exists in this scope.

#### 🛠️ Function <PARTIAL_CHECK_FN> (<PARTIAL_CHECK_ADDR>) — Isolated Owner Check
* Checks account ownership at `<OWNER_CHECK_SITE>` utilizing the string constant `" is not owned by "` (`<OWNER_STR_ADDR>`).
* **The Gap:** This validation rule is exclusively applied to a specialized subset of account types. Multiple routing paths skip this validation entirely.

#### 🛠️ Entrypoint <DISPATCH_ADDR> Jump Table Gap
* Register `r1` functions as the instruction discriminator index, jumping execution routines dynamically into the program's jump table (`<HANDLER_TABLE>`).
* **Static Analysis:** Discovered open validation gaps across instructions at indices: `<STATIC_LIST>`.
* **Dynamic Simulation:** Confirmed active validation skips on handlers: `<CONFIRMED_LIST>`.
* *Note:* Remaining indices are caught early by general dispatcher constraints throwing `Custom(<UNIMPL_CODE>)` and are classified as inconclusive.

---

### 📊 DYNAMIC SIMULATION & PARALLEL TESTING

When loading the real SBF program binary under `solana-program-test` with an unvalidated account structure owned completely by an external attacker Keypair, the runtime logged the following execution behaviors:

* **Business-Check Handlers (Handlers 0-3):** 
  * *Status:* **VULNERABLE** — Handler body successfully entered.
  * *Metrics:* Low compute unit cost (~542 CU), failing at `InstructionError(0, Custom(<BIZ_CODE>))`. 
  * *Security State:* No structural ownership rejection is thrown at the boundary layer.
* **Signer-Gated Handlers (Handler 4):** 
  * *Status:* **VULNERABLE** — Handler body successfully entered.
  * *Metrics:* High compute unit cost (~13,516 CU), failing at `Custom(<SIGNER_CODE>)`. 
  * *Security State:* The transaction traverses deep logic and is safely halted by a cryptographic PDA signer gate, not an owner validation.
* **Remaining Discriminators:** 
  * *Status:* **INCONCLUSIVE** — Transaction rejected at the root dispatcher layer with `Custom(<UNIMPL_CODE>)` at low CU (~483 CU). No inner handler log or execution trace was emitted.

---

### 🛡️ PARAMETER BOUNDARY ESALATION TESTING

The initial failure code `Custom(<BIZ_CODE>)` on early handlers represents an external token account validation step that any standard caller can satisfy. 

A follow-up test successfully provisioned active SPL mint layouts, a real token balance, and a mock program-owned vault structure. 

```text
[Escalation Run Profile: Handler 0 With Satisfied SPL Topologies]
  » amount = 1             │ Write: false │ Status: Halt -> Custom(<SIGNER_CODE>)
  » amount = 1000          │ Write: false │ Status: Halt -> Custom(<SIGNER_CODE>)
  » amount = 1000000000    │ Write: false │ Status: Halt -> Custom(<SIGNER_CODE>)
  » amount = 1000000000000 │ Write: false │ Status: Halt -> Custom(<SIGNER_CODE>)
  » amount = u64::MAX / 2  │ Write: false │ Status: Halt -> Custom(<SIGNER_CODE>)
```

#### 💡 Architectural Implications
By satisfying the token dependencies, the execution pipeline processed malicious attacker-controlled bytes **significantly deeper** into the function core, multiplying compute unit usage **25x deeper** before halting at the cryptographic PDA signer boundary (`Custom(<SIGNER_CODE>)`). 

Because Solana's runtime strictly bars account data serialization back to an address the executing program does not own, `write=false` remained true across all numerical limits, ensuring zero exploitability for capital theft. The `<SIGNER_CODE>` gate is strictly cryptographic, not a business rule, and cannot be bypassed from outside the environment.

---

### ⚠️ IMPACT STATEMENT
The dispatcher forwards arbitrary account structures into internal function scopes without verifying `account.owner == program_id`. Any caller can introduce fully controlled byte matrices that the contract processes as valid program state. While existing handlers are insulated downstream by tight cryptographic signer criteria, the root of trust is completely absent. Any newly engineered instruction added to this router layout without manual protection will implicitly inherit this entrypoint zero-day gap.

---

### 💡 RECOMMENDED FIX
Implement unified owner validation inside the root entrypoint dispatcher assembly loop (`<DISPATCH_ADDR>`). Before assigning routing paths or iterating values, verify account ownership once across every supplied account index:

```rust
if account.owner != program_id {
    return Err(ProgramError::AccountOwnedByWrongProgram.into());
}
```

---

### 🛠️ LAB REPRODUCTION FRAMEWORK

#### Workspace Architecture
```text
<CRATE_NAME>/
├── Cargo.toml
└── tests/
    ├── exploit_test.rs
    └── fixtures/
        └── target_program.so
```

#### Environment Dependencies (`Cargo.toml`)
```toml
[package]
name = "<CRATE_NAME>"
version = "0.1.0"
edition = "2024" # Requires rustc 1.18.x or newer

[dependencies]
borsh = "1.5"
spl-token = { version = "4.0", features = ["no-entrypoint"] }

[dev-dependencies]
solana-program-test = "1.18"
solana-sdk = "1.18"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

#### Verification Execution
```bash
cargo test --test exploit_test -- --nocapture
```
