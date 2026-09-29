# K-102 owner review

Reviewed graphd source diff from 90c5865 through 7156979 and task evidence. Query/render now use the repository binding root where publication writes after validating the project membership subdirectory. The real C# fixture exposed the prior path mismatch; the candidate query and watcher generation now pass. Schema 99 is refused with export-unsupported; package tests refuse corrupt archives, wrong revision and incompatible manifest version.

Compatibility: graph schema/control API/queue schema remain version 1; output location matches existing writer. Existing user installations and release declarations were not changed. Rollback is reverting the source branch; no installed state was touched. Changelog, Development and build matrix were updated. `git diff --check` and a changed-file credential scan passed. Independent reviewer execution remains pending before main integration.
