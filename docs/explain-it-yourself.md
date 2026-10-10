# Explain it yourself

Questions to answer out loud, without notes, before VulnScan goes near a
resume or an interview. There are no answers here: the explanation has to
be mine. VulnScan was built with Claude, so the bar is explaining why it is
built this way and what went wrong, not only what the code does. Python is
on my language list, so once I can answer these unaided VulnScan can go on
a resume like any other project.

## Run it first

1. `make update`, then `make scan TARGET=../papertrail-rag`. Read the text
   report from the top. Pick one dependency finding and say where its
   version came from (which file, which line, how sure), which advisories
   were merged into it, why its severity is what it is, and what the fix
   line tells you to do.
2. `PYTHONPATH=src .venv/bin/python -m vulnscan scan ../papertrail-rag
   --format json` and find the secret finding. What does the output show
   about it, and what does it never show? Why is its state `uncommitted`,
   and why does that not fail the scan?
3. Pick a package and version from a finding and run `make lookup` for it.
   Then look up a version below where the advisory's first range starts,
   and the version it says fixes it. Explain each answer from the
   advisory's ranges.
4. Scan `../linkforge-fullstack` on `main`, then on the branch
   `fix/compose-databases-localhost`. Which findings disappear, and why?
   What could someone on the same café network do with the `main` version
   while `docker compose up` is running?
5. When Docker works: `make smoke`. Pick three of its checks and say what
   each proves. Why is the target mounted read-only and the network turned
   off; what would each catch if VulnScan misbehaved?

## Dependencies

6. Why does VulnScan trust an installed `.venv` over `pyproject.toml`?
   When would the venv give the wrong answer about what CI or production
   runs?
7. `fastapi>=0.142` is "declared" and never matched against advisories.
   Why not match its lowest version? What would that do to the report?
8. Put these in PEP 440 order and say why: `1.0`, `1.0.post1`, `1.0a1`,
   `1.0.dev1`, `1.0+local`, `1.0rc1`. Where in `versions/pep440.py` is
   each of those decided?
9. An OSV range has the events `introduced 0`, `fixed 2.0`,
   `introduced 2.1`, `last_affected 2.3`. Walk it for 1.9, 2.0, 2.2, 2.3
   and 2.4. Why must the events be sorted by version before the walk?
10. Why are there three answers (affected, not affected, unknown) and not
    two? Take a torch advisory whose range ends at "2.6.0-cu124": what
    would it take to decide it, and why does VulnScan refuse to?
11. Score `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` by hand. What
    changes when the scope is Changed? What is the specification's Roundup
    for, and why not `math.ceil`?
12. Why does one bug listed under a GHSA id, a GO id and a CVE become one
    finding, while the same package in two environments is two?
13. The first comparison with osv-scanner found 78 advisory groups
    VulnScan missed. What were they, why were they missed, and why are 26
    of the 151 now "version only"? After the fix the tools agree exactly:
    is that independent evidence that VulnScan is right? Why not?

## Secrets

14. Why does VulnScan read `.git` by hand instead of running `git`? Name
    the setting that would let a repository run a program on the machine
    of anyone who runs git in it.
15. Explain how git stores objects: loose objects, pack files and their
    indexes, offset deltas and reference deltas. How does VulnScan know it
    read an object correctly?
16. Why is each blob scanned once and then mapped back to its paths and
    commits? What does the history walk visit, and what does it never see?
17. Name the five states. Why does `uncommitted` pass and `in-git` fail?
    Tell failure 14: what iCloud did, what the code concluded, and why it
    was dangerous even though no output was wrong.
18. Why is the fingerprint PBKDF2 with 100,000 rounds and not one SHA-256?
    Who is the attacker, and what do they have?
19. Why does VulnScan never ask a provider whether a token is live? What
    would that gain, and what would it cost?
20. Failure 10: why was every `KEY=token` line missed, and why may `=`
    come before a token but no other token character may?
21. The assignment rule needs 3.5 bits of entropy per character over 16+
    characters. Roughly what is the entropy of `aaaaaaaabbbbbbbb`, and of
    16 random letters and digits? What does the threshold trade away?
22. Skipping a format whose literal is not in a file halved the scan. Why
    can that never lose a finding, what has to stay true of every format,
    and what keeps a new format from breaking it?

## Dockerfiles and Compose files

23. Why is the Dockerfile parser checked against BuildKit and not against
    the `dockerfile-parse` library? Give the example that showed the
    difference.
24. Why a hand-written YAML subset that refuses things, instead of PyYAML?
    What does it refuse, and why is refusing better than a best guess?
25. `"5432:5432"` against `"127.0.0.1:5432:5432"`: what is the difference
    on this laptop at home and on a shared network? Why did it matter in
    LinkForge even though the password is only a development default?
26. `runs-as-root` judges only the images a Dockerfile makes. Why? And
    why does a healthcheck in a Compose file not silence `no-healthcheck`;
    what would it take to make it?

## Reports and CI

27. Exit codes 0, 1 and 2. Why is "no advisory data for an ecosystem the
    repository uses" exit 2 rather than 0?
28. An acceptance needs a reason and an expiry date. What happens the day
    after it expires? Why are acceptances that match nothing reported?
29. What is `security-severity` in the SARIF, who reads it, and how is it
    computed here?

## Measuring

30. The scan-time benchmark measures warm scans, in interleaved passes,
    with a swap check per run. Why each of those? What would a cold scan
    of this iCloud folder measure instead?
31. Failure 21: a results file with a broken CPU column was deleted
    instead of kept. Why does this portfolio keep bad runs, and what
    should have been done with it?
32. "Every finding labelled by hand" gives precision. Why is recall not
    measured, and what evidence is there about what VulnScan misses?

## The two that matter in an interview

33. One design decision I would defend, in my own words, and what it
    costs.
34. One failure mode I found, told as a story: the symptom, the cause, the
    fix, and the test that now guards it.
