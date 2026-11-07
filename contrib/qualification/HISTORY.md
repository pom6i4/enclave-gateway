# Historical qualification evidence

Historical reports describe their recorded source and fixture, not the current product.
They remain in Git history; they are deliberately absent from the active user documentation.
Original failing private logs and retained lab storage were not removed.

## 0.3.0 Beta 3

- Operator chunked-copy acceptance exercised source revision
  `d5a6fb003cec63ffbf9b230a4424adca28988bf8` on an isolated Windows Server 2022
  x64 RDP route with KES 14.1.0.423. All 136 blocks at 3 MiB and 65 MiB in both
  directions met the 15 s limit, with a 2.692 s maximum. The complete file
  hashes matched. No new KES events or added exclusions were recorded.
- A separate local portable fixture exercised 512 MiB in both directions.
  It measured 36.022 s upload and 46.780 s download. This fixture used local pipes.
- The PowerShell-enabled suite found 329 tests. 313 passed and 16 were skipped.
  The source and Python release binds the later documentation and version
  commit. [Test scope](../../docs/ENDPOINT-POLICY.md#operator-backend-under-kes-141)
  [Release procedure](../../docs/RELEASING.md)

## Snapshot before the public-product documentation reorganization

- [AUTONOMOUS_ACCEPTANCE_2026-11-01.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/AUTONOMOUS_ACCEPTANCE_2026-11-01.md)
- [AUTONOMOUS_CLOSURE_2026-11-02.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/AUTONOMOUS_CLOSURE_2026-11-02.md)
- [AUTONOMOUS_QUALIFICATION_2026-11-01.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/AUTONOMOUS_QUALIFICATION_2026-11-01.md)
- [COLD_SECURITY_QUALIFICATION_2026-11-01.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/COLD_SECURITY_QUALIFICATION_2026-11-01.md)
- [EXTENDED_QUALIFICATION_2026-11-02.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/EXTENDED_QUALIFICATION_2026-11-02.md)
- [FRESH_INSTALL_ACCEPTANCE_2026-11-02.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/FRESH_INSTALL_ACCEPTANCE_2026-11-02.md)
- [FUNCTIONAL_HARDENING_2026-10-31.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/FUNCTIONAL_HARDENING_2026-10-31.md)
- [FUNCTIONAL_QUALIFICATION_2026-10-31.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/FUNCTIONAL_QUALIFICATION_2026-10-31.md)
- [LOCAL_QUALIFICATION_2026-10-31.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/LOCAL_QUALIFICATION_2026-10-31.md)
- [REPRODUCIBLE_QUALIFICATION_2026-11-02.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/REPRODUCIBLE_QUALIFICATION_2026-11-02.md)
- [SECURITY_AUDIT_2026-10-31.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/SECURITY_AUDIT_2026-10-31.md)
- [WINDOWS_LAB_QUALIFICATION_2026-11-01.md](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/WINDOWS_LAB_QUALIFICATION_2026-11-01.md)
- [unsigned-1eb710b.cdx.json](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/qualification/unsigned-1eb710b.cdx.json)
- [unsigned-346208c.cdx.json](https://github.com/pom6i4/enclave-gateway/blob/551590cfc68049261a948a9072a141ebfebb4343/docs/qualification/unsigned-346208c.cdx.json)
