# 0day-research-dummy

‎MISSING ACCOUNT OWNER VALIDATION AT ENTRYPOINT DISPATCHER — CRITICAL
‎
‎CVE-Candidate: No owner check before account data access
‎
‎Program: <TARGET PROGRAM>
‎Program ID: <TARGET_PROGRAM_ID>
‎Faulty site: entrypoint dispatcher <DISPATCH_ADDR>
‎
‎Note: This Research/PoC Was Done For A Real 0day This research is published for educational and defensive purposes.
‎
‎Function <ITER_FN> (<ITER_FN_ADDR>) — Account data iterator
‎Iterates a fixed-length window into account data at [r2+offset] looking for null terminators.
‎No owner comparison. Only checks ldxb r0, [r3] for 0x00 and ldxb r0, [r2+1] / [r2+2] for terminator bytes.
‎Error strings "is not a signer" (<SIGNER_STR_ADDR>) and "is not writable" (<WRITABLE_STR_ADDR>) are present, but no "is not owned by" check exists in this function. Owner validation is missing.
‎
‎Function <PARTIAL_CHECK_FN> (<PARTIAL_CHECK_ADDR>) — Partial owner check
‎Checks owner at <OWNER_CHECK_SITE> with string " is not owned by " (<OWNER_STR_ADDR>), but only for a subset of account types. The entrypoint dispatches multiple instruction variants, and several handlers skip owner validation entirely.
‎
‎Entrypoint <DISPATCH_ADDR> dispatch gap
‎r1 = instruction index jumps to handlers at <HANDLER_TABLE>. Static analysis identified candidate gaps at indices <STATIC_LIST>. Dynamic testing confirmed the gap at <CONFIRMED_LIST>. Remaining indices are rejected at the dispatcher level before any handler body runs, so they could not be dynamically confirmed and are treated as inconclusive rather than vulnerable.
‎
‎Dynamic confirmation
‎PoC loaded the real SBF binary under solana-program-test and submitted transactions containing an account whose owner field was set to a fresh attacker Keypair, not the program. Results across all discriminators:
‎
‎- business-check handlers: handler body entered, low CU, failed InstructionError(0, Custom(<BIZ_CODE>)). No ownership rejection.
‎- signer-gated handler: handler body entered, high CU, failed Custom(<SIGNER_CODE>). The failure is a PDA signer check on a program-derived address, not an owner check.
‎- remaining discriminators: rejected at dispatcher level with Custom(<UNIMPL_CODE>) at low CU, no handler log emitted. Classified as inconclusive, not vulnerable.
‎
‎Escalation with real SPL token accounts
‎The initial Custom(<BIZ_CODE>) was a token-account / mint validation satisfiable by any caller. A follow-up test supplied a real SPL mint, a real attacker-owned token account with balance, a program-owned vault, and the SPL token program ID. The handler then progressed past <BIZ_CODE> to Custom(<SIGNER_CODE>) at much higher CU — significantly deeper execution against the same attacker-owned state account. The final failure is a PDA signer check that cannot be satisfied by an external caller. No state write occurred (write=false across all amounts tested).
‎
‎This confirms the missing owner check is not merely blocked by a first-line business check: the handler accepts and processes attacker-controlled state deeply into its logic before any signer gate halts execution. The <SIGNER_CODE> gate is cryptographic (PDA-derived signature), not a business rule, and cannot be bypassed from outside the program.
‎
‎Confirmed vulnerable handlers: <CONFIRMED_LIST>.
‎
‎Impact
‎The dispatcher forwards accounts into handler bodies without verifying that account.owner equals the program ID. Any caller can supply an account whose bytes they fully control, and the handler will treat it as program state. Handlers without a PDA gate execute against attacker-supplied state and only fail on internal business checks that any caller can satisfy (as demonstrated by the SPL token escalation). The signer-gated handler cannot be reached externally. The root of trust for all state reads at this entrypoint is absent. Any privileged instruction added to this dispatcher without an explicit owner check inherits the same gap.
‎
‎Recommended fix
‎At the entrypoint dispatcher, before routing to any handler, verify account.owner == program_id for every account passed in the instruction. Enforce this in a single check performed once per account, not per handler, so no handler can be added that bypasses it.
‎
‎REPRODUCTION
‎
‎Repository layout:
‎  <CRATE_NAME>/
‎    Cargo.toml
‎    tests/
‎      exploit_test.rs
‎      fixtures/
‎        target_program.so
‎
‎Toolchain (as tested):
‎  rustc 1.85+ (edition 2024)
‎  cargo 1.85+
‎  solana-program-test 1.18.26
‎  solana-sdk 1.18.x
‎  spl-token 4.0.x (features: no-entrypoint)
‎  borsh 1.5.x
‎  tokio 1.x (features: macros, rt-multi-thread)
‎
‎Cargo.toml:
‎  [package]
‎  name = "<CRATE_NAME>"
‎  version = "0.1.0"
‎  edition = "2024"
‎
‎  [dependencies]
‎  borsh = "1.5"
‎  spl-token = { version = "4.0", features = ["no-entrypoint"] }
‎
‎  [dev-dependencies]
‎  solana-program-test = "1.18"
‎  solana-sdk = "1.18"
‎  tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
‎
‎  Note: edition 2024 requires rustc 1.85 or newer.
‎
‎Build and run:
‎  cargo test --test exploit_test -- --nocapture
‎
‎Expected output:
‎  test exploit_missing_owner_validation_handler_0 ... ok
‎  test scan_all_handlers_for_missing_owner_validation ... ok
‎  test exploit_set_handler_signer_gate ... ok
‎  test escalation_with_real_token_accounts ... ok
‎
‎  SUMMARY
‎  VULNERABLE (handler reached with attacker-owned account): <CONFIRMED_LIST>
‎  SAFE (owner check enforced): []
‎  INCONCLUSIVE (rejected before handler body): <INCONCLUSIVE_LIST>
‎  Confirmed vulnerable discriminators: <N>
‎
‎  escalation: handler 0 with real SPL token accounts
‎  amount=<value>   cu=<high>  write=false status=Custom(<SIGNER_CODE>)
‎  amount=<value>   cu=<high>  write=false status=Custom(<SIGNER_CODE>)
‎  amount=<value>   cu=<high>  write=false status=Custom(<SIGNER_CODE>)
‎  amount=<value>   cu=<high>  write=false status=Custom(<SIGNER_CODE>)
‎  amount=<value>   cu=<high>  write=false status=Custom(<SIGNER_CODE>)
‎
‎Notes:
‎  The PoC loads the program binary from tests/fixtures/target_program.so.
‎  The find_program_elf() helper auto-discovers the .so across several common
‎  paths, so the test runs from the crate root without environment setup.
‎
‎Test file:
‎  tests/exploit_test.rs
