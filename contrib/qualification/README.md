# Maintainer qualification

This area is for reproducible isolated labs, not the first-run product path.
Start users at [GUIDE.md](../../docs/GUIDE.md) and
[SECURITY.md](../../docs/SECURITY.md). An ordinary install needs neither filled
qualification plans nor historical reports.

- [Local and installed-distribution checks](LOCAL_ACCEPTANCE.md)
- [Independent builds and full installation](REPRODUCIBLE_ACCEPTANCE.md)
- [Extended runtime profile](EXTENDED_ACCEPTANCE.md)
- [Backend isolation and release procedure](HARDENING_AND_QUALIFICATION.md)
- [Historical source-bound records](HISTORY.md)

Safe unfilled plan templates live in `plans/`. Runtime runner code remains under
`scripts/qualification/`. Supply approved tools, media hashes and disposable
fixture identities yourself. Store filled plans, credentials and raw evidence in
private ignored storage. No client environment or production key is required by
the generic lab tooling. Never promote an old receipt to acceptance of new source.

Tests exercise runner invariants without depending on named historical Markdown
files. Keep failed runs, perform owned-resource cleanup and report exact source,
architecture, skips, observer budgets and acceptance boundaries. A successful
component or repaired observer is not a complete full-profile PASS.
