# Source and contribution record

Technical source: [microsoft/sarif-python-om](https://github.com/microsoft/sarif-python-om) at fixed commit `f99b8edb126e2a4ad8a61ffee63113887a6af035`. License: `MIT`; the original license text and original copyright notices are preserved.

New implementation author: **dhtfish98**. This project implements the explicitly selected standalone scope below. It is not presented as original ownership of the upstream algorithms or as a full rewrite of an upstream platform. No source files have merely been renamed into the runtime package.

Scope: SARIF 2.1.0 selected driver/rule/artifact physical-location relations, required record shapes, duplicate-key rejection, rule-id/index consistency, artifact-index bounds and region ordering/ranges.

The upstream entry points, format layouts and relevant default file/network/execution paths were inspected in the fixed files listed in SOURCE_MANIFEST.json. Complete new runtime files are reviewed separately; this does not imply audit of unselected upstream platform code.

Excluded upstream capabilities: Full schema conformance, tool extensions, logical location semantics, external properties, fetching artifact URIs, truth of alerts and generated object-model API equivalence.

The repository owner must verify their actual contribution and authorization before using this record in an application. No CVE, rejected-model task, CVP acceptance or personal identity evidence has been invented.
