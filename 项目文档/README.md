> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# SarifLinkReview

New implementation author: **dhtfish98**. Current package version: **1.0.2**.

Checks unusable or inconsistent scanner reports before incident triage while suppressing messages and artifact paths. External/unresolved rule metadata stays OPEN.

## Supported project scope

SARIF 2.1.0 selected driver/rule/artifact physical-location relations, required record shapes, duplicate-key rejection, rule-id/index consistency, artifact-index bounds and region ordering/ranges. Redundant legacy/`result.rule` IDs and indices must agree. Driver rule IDs may carry one additional hierarchical component. URI-base maps are checked for shape, cycles, depth, bounded concatenation and declared parent chains. URI/index identity is checked after base resolution, without fetching files. The URI comparison profile supports simple ASCII relative paths and `file`, `http` and `https` URIs; percent encoding, query/fragment components, dot segments, complex authorities and other schemes remain OPEN. Unknown bases and redacted base roots remain OPEN. Message-ID lookup, modern rule references that omit a lookup index, GUID/tool-component selectors and nested-artifact semantics remain OPEN. Present selected fields cannot use JSON null as a substitute for omission. URI processing has a report-wide 16 MiB character budget, including base expansion and artifact references, with at most 64 base links and 65,536 characters per resolved URI.

This repository implements that entire selected standalone scope. It does not claim that the original upstream platform has been rewritten in full.

## Use

```sh
python -m pip install .
sariflinkreview examples/valid.bin
```

Supply one local regular file. The file CLI requires OS `O_NOFOLLOW` and `O_NONBLOCK` support; missing safety flags return OPEN before opening the path. This file-reader contract was verified on macOS/Linux; native Windows file reading is outside the validated profile. No symlinks or automatic artifact discovery are accepted. The CLI prints JSON; exit 0 means supported checks completed, exit 1 means a structural failure, and exit 2 means unsupported/incomplete analysis. Each successful read includes the input SHA-256 and byte count. Paths, contents, report messages and identities are suppressed. The input is never modified.

## Explicit limits and boundaries

Input limit: 16 MiB. Record limit: 100,000. Additional format-specific limits are enforced in the source.

Excluded capabilities: Full schema conformance, tool extensions, logical location semantics, external properties, fetching artifact URIs, truth of alerts and generated object-model API equivalence.

PASS only describes the recorded checks. It does not prove real-world safety, historical activity, authenticity, applicant contribution or CVP approval. CVP application suitability/qualification remains OPEN until the applicant supplies the real authorized work, relevant restriction evidence and identity/organization facts.

## Provenance and validation

See [ORIGIN.md](<ORIGIN.md>), [SOURCE_MANIFEST.json](<../SOURCE_MANIFEST.json>), [VALIDATION.md](<VALIDATION.md>) and the preserved [LICENSE](<LICENSE>).
