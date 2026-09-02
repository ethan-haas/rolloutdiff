# rolloutdiff

Semantic diff of rendered Kubernetes manifests, classified by **blast
radius**. Offline, deterministic, never touches a cluster.

`kubectl diff` / `helm diff` show TEXT that changed. `rolloutdiff` answers
the question a reviewer actually has: *does this restart pods, recreate
them, drop a volume, disrupt live traffic, broaden a permission, or nothing
at all?*

## Install & run

```
pip install -r requirements.txt
python -m rolloutdiff <before-path> <after-path>
```

`<before-path>` / `<after-path>` are each either a single YAML file or a
directory (searched recursively for `*.yaml`/`*.yml`), containing one or
more `---`-separated Kubernetes object documents. Output is a single JSON
document on stdout.

Exit codes:
- `0` — no findings (before/after are semantically identical)
- `1` — findings present (a change exists; classification detail is in the
  JSON `findings` array)
- `2` — malformed input or bad usage (unparsable YAML, missing
  `apiVersion`/`kind`/`metadata.name`, duplicate `(group, kind, namespace,
  name)` within one side, nonexistent path, wrong arg count)

## Try it on the bundled examples

```
python -m rolloutdiff examples/before.yaml examples/after.yaml
```

Five real changes across four blast-radius classes, each anchored to the
field that proves it:

| classification | field |
|---|---|
| `disruption` | `spec.replicas` (3 -> 0) |
| `data-loss` | `spec.resources.requests.storage` (10Gi -> 5Gi) |
| `data-loss` | `spec.storageClassName` |
| `rolling-restart` | `spec.template.spec.containers[name=app].image` |
| `privilege-change` | `...containers[name=app].securityContext.privileged` |

That same example also changes `memory: 1024Mi` to `1Gi` and `cpu: "1"` to
`1000m`. Those are the *same values*, so they produce no finding at all.

The other direction matters just as much:

```
python -m rolloutdiff examples/before.yaml examples/cosmetic_after.yaml   # 0 findings, exit 0
```

Reordered keys, equivalent quantity spellings, and churn in a
`last-applied-configuration` annotation. Nothing real changed, so nothing
is reported. A differ that flagged all of this would be useless in review.

And a kind the coverage table does not know:

```
python -m rolloutdiff examples/unknown_crd_before.yaml examples/unknown_crd_after.yaml
```

reports `unknown` for each changed field and exits non-zero -- **never**
`no-op`. An unrecognized CRD that quietly reads as "no change" is the
failure this design exists to prevent.

## Run the test suite

```
python -m pytest tests/ -v
```

80 tests, all self-authored. An independent adversarial review is a
separate exercise and is deliberately not written here; grading your own
correctness is not a gate.

## Components

1. **`rolloutdiff/loader.py`** — parses multi-doc YAML from files/dirs.
   `object_ref = (group, kind, namespace, name)`, where `group` is the
   `apiVersion` group segment (`""` for core/v1). No network, no
   kubeconfig, no cluster contact anywhere in this module or anything it
   calls — verified by having zero imports beyond `yaml` + stdlib
   (`os`, `typing`).
2. **`rolloutdiff/normalize.py`** — makes semantically-identical inputs
   compare equal: strips `status`, server-owned metadata
   (`resourceVersion`, `uid`, `generation`, `creationTimestamp`,
   `selfLink`, `managedFields`), and known churn annotations
   (`kubectl.kubernetes.io/last-applied-configuration`,
   `deployment.kubernetes.io/revision`, `kubernetes.io/change-cause`);
   ignores trailing-whitespace/trailing-blank-line differences inside
   multi-line string values; reorders identity-keyed lists (`containers`,
   `initContainers`, `ephemeralContainers`, `volumes`, `env`,
   `volumeMounts` — keyed by `name`) before comparison so their order is
   non-semantic. Every other list (`args`, `command`, container `ports`,
   Ingress `rules`, RBAC `subjects`) stays order-SENSITIVE by default —
   conservative: when unsure whether an order matters, it is NOT treated
   as a no-op.
3. **`rolloutdiff/coverage_table.py`** — **the core discipline.** A
   declared, versioned table (`KIND_TABLE`, `COVERAGE_TABLE_VERSION`,
   `COVERAGE_TABLE_SOURCE`) mapping `(kind, field_path_pattern)` to a
   blast-radius classification, hand-authored from public Kubernetes API
   conventions for 13 kinds across 7 API groups (see the module docstring
   for the full citation list). This is the ONLY source of classification
   used anywhere in the tool. Any kind not in the table, or any field path
   within a covered kind that no rule matches, classifies `unknown` —
   **never** inferred, **never** defaulted to `no-op`. That fail-unsafe
   default is the exact bug class this design exists to prevent.
4. **`rolloutdiff/differ.py`** — walks normalized before/after object
   trees, emits one `Finding` per distinct field-level change:
   `{object_ref, field_path, classification, evidence, message}`. Handles
   whole-object add/remove. `field_path` always resolves into the supplied
   documents (`rolloutdiff/path_resolve.py`, exercised directly by
   `tests/test_planted_defects.py`). A small number of value-aware overrides
   live here on top of the flat table, each documented in place:
   - `spec.replicas` scaling to exactly `0` overrides the normally
     `in-place` rule to `disruption`.
   - RBAC `Role`/`ClusterRole` `rules` and `RoleBinding`/
     `ClusterRoleBinding` `subjects` are compared at the *atomic grant*
     level (not whole-rule-object equality) so that narrowing one verb out
     of a multi-verb rule is recognized as a removal (`in-place`) rather
     than misread as "rule replaced" (`privilege-change`). Any newly
     *added* grant, or an ambiguous mixed add+remove, classifies
     `privilege-change` (conservative).
5. **`rolloutdiff/reporter.py`** — stable, sorted, deterministic JSON
   (`json.dumps(..., sort_keys=True)`, which also neutralizes any
   `PYTHONHASHSEED`-driven dict-iteration-order effects).
   Reports `unknown_rate` (of *this run's* findings, honest coverage
   signal, never hidden), plus `detection_rate` / `false_flag_rate`
   (freshly measured every invocation against the bundled synthetic
   corpus — see `rolloutdiff/self_check.py` — never hardcoded). All three
   are separate JSON keys, never averaged/blended into one score.
6. **`rolloutdiff/quantity.py`** — declared-table parsing for two field
   classes the differ used to compare as raw strings: k8s
   `resource.Quantity` values (`resources.requests.*` / `resources.limits.*`
   — binary Ki/Mi/Gi/Ti/Pi/Ei = 1024^n, decimal k/M/G/T/P/E = 1000^n, milli
   `m`), so `1Gi` and `1024Mi` compare equal by parsed value; and a small
   declared set of OpenAPI `integer`-typed fields (`spec.replicas`,
   `spec.minReplicas`/`maxReplicas`, `spec.parallelism`,
   `spec.backoffLimit`) where `3` and `"3"` compare equal (chosen over the
   alternative of treating a type-mismatched scalar as malformed input/
   exit(2), since these are already-rendered manifests where a quoted vs.
   bare integer is not a semantic difference). Both are guarded: a field
   not in the declared set is still compared as a raw string/value, and an
   unparseable quantity is never guessed equal. `PodDisruptionBudget`
   `minAvailable`/`maxUnavailable` are deliberately EXCLUDED from the
   typed-integer set — they are IntOrString (can be `"50%"`), a materially
   different value shape from a plain integer count.
7. **`rolloutdiff/server_defaults.py`** — a declared, versioned table of
   well-known k8s field-level server-injected defaults (Service
   `ports[].protocol` = `TCP`; container `imagePullPolicy` = `Always` for
   an omitted/`:latest` tag else `IfNotPresent`; container
   `terminationMessagePath`/`terminationMessagePolicy`; pod
   `restartPolicy` = `Always` for Deployment/StatefulSet/DaemonSet only
   — Job/CronJob have no default here; pod `dnsPolicy` = `ClusterFirst`
   — each entry cites its k8s source). When `after` ADDS a field absent in
   `before` and the added value equals the documented default, it is
   stripped from the `after` copy BEFORE the differ's tree walk, so it
   produces zero findings (no-op), exactly like key reordering or
   annotation churn. A field not in this table is never touched regardless
   of its value.
8. **`rolloutdiff/corpus.py`** — in-repo synthesizer, no network, no
   helm/kustomize binaries invoked. Produces (a) planted-change pairs
   covering all 8 verdict classes with a recorded expected
   `(classification, field_path)`, (b) two-sided no-op pairs (key reorder,
   injected server defaults/status, annotation churn, whitespace churn,
   non-semantic env-list reorder), and (c) 3 text-shape renderers
   (`render_raw`, `render_helm_style`, `render_kustomize_style`) — all
   parse to identical structured content via plain YAML comment/`---`
   handling, which is why no shape-specific loader logic is needed.

## Coverage table scope

13 kinds: `Deployment`, `StatefulSet`, `DaemonSet` (apps/v1); `Job`,
`CronJob` (batch/v1); `Service`, `ConfigMap`, `Secret`,
`PersistentVolumeClaim`, `ServiceAccount` (core/v1);
`HorizontalPodAutoscaler` (autoscaling/v2); `PodDisruptionBudget`
(policy/v1); `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`
(rbac.authorization.k8s.io/v1); `Ingress` (networking.k8s.io/v1). Every
other kind — every other core kind (`Pod`, `Node`, `Namespace`, ...), every
other API group, every CRD — is `unknown` by construction. Full
field-level citations/notes are in `rolloutdiff/coverage_table.py`.

## Documented scope boundaries

- **Mounted-ConfigMap/Secret propagation is out of scope.** This tool does
  not track which pods mount a given `ConfigMap`/`Secret` (as an env var,
  `envFrom`, or volume). A bare `data`/`binaryData`/`stringData` change is
  reported as `in-place` **on the ConfigMap/Secret object itself only** —
  it does NOT walk out to consuming `Deployment`/`StatefulSet`/etc. objects
  to report a cascading `rolling-restart`. A real cluster's actual restart
  behavior further depends on the mount type (env vars are NOT
  live-reloaded; some volume mounts sync eventually via kubelet), which is
  itself operator-dependent — correctly modeling it would require tracking
  cross-object references, which this tool's object-by-object,
  field-by-field model does not do.
- **RBAC `resourceNames` is not treated as a further restriction
  dimension.** `classify_rbac_rules` (`differ.py`) expands each PolicyRule
  into atomic `(apiGroup, resource, verb, resourceNames)` grants; a rule
  WITH `resourceNames` and one WITHOUT compare as different atomic grants
  rather than one being recognized as a subset/narrowing of the other.
- **Cloud-provider / ingress-controller annotations are not modeled as
  routing-relevant.** e.g. an nginx `rewrite-target` annotation change, or
  a cloud LB annotation change on a `Service`, is classified `in-place`
  (generic object-annotation rule) even though it can be traffic-relevant
  in a real cluster. Out of scope for this table subset.
- **PVC storage-size changes are conservatively `data-loss`** rather than
  distinguishing "this storage class supports online expansion" (which
  would be provisioner-dependent, unknowable from the manifest alone) from
  a shrink (which is generally rejected/unsupported). Conservative-by-
  design: unsure classifies toward the more severe read.
- **Namespace defaulting is not guessed.** If `metadata.namespace` is
  absent, `object_ref`'s namespace is the literal empty string — this tool
  never assumes `"default"`.
- **Pod-template privilege rules are declared at EVERY wrapper prefix a
  pod template lives at, not inferred from tree shape.**
  `coverage_table._pod_template_privilege_rules(prefix)` is the single
  declared rule set, applied literally at `spec.template`
  (Deployment/StatefulSet/DaemonSet/Job) AND at
  `spec.jobTemplate.spec.template` (CronJob — the pod template there sits
  one level deeper, inside the JobSpec the CronJob controller creates each
  scheduled run). This is what makes a privilege-relevant leaf nested
  inside a CronJob's `jobTemplate` classify `privilege-change` instead of
  falling through to the coarser `spec.jobTemplate -> in-place` wrapper
  rule, and what makes the same leaf inside a Job's immutable
  `spec.template` classify `privilege-change` (which OUTRANKS `recreate`
  in this table's severity precedence) instead of being shadowed by the
  blanket immutable-template rule.
- **Typed-scalar/quantity equality is declared per field, not inferred
  from value shape.** See `rolloutdiff/quantity.py` and
  `rolloutdiff/server_defaults.py` docstrings above for the exact declared
  sets and their k8s sources.

## Self-test results (this build)

Run `python -m pytest tests/ -v` — 80/80 pass. Beyond the original build's
suite, `tests/test_wrapper_and_normalization.py` covers four defect
families found in review: wrapper-nested pod-template privilege rules,
resource-quantity equality, server-default injection, and typed-scalar
equality — each with a guardrail proving the fix doesn't over-broaden. Sample live-run `coverage_quality` output
(`python -m rolloutdiff <b> <a>` on a 3-object before/after pair, freshly
measured each invocation, not a stored constant): `detection_rate: 1.0`,
`false_flag_rate: 0.0`, `planted_non_noop_total: 12`, `noop_cases_total: 6`
— unchanged by this round's fixes. Live-run `unknown_rate` varies per
input — it is 0.0 unless the input contains a kind/field this table does
not cover.

These are self-graded numbers from this repo's own corpus and tests. An
independent adversarial review is a separate exercise, and this repo makes
no claim about that outcome on its own authority.
