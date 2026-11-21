# Opt-in Salesforce sf data command risk rules

`command.salesforce.sf` is an external command contribution for the
`sf data` commands in `@salesforce/plugin-data` 5.1.10, as bundled by
`@salesforce/cli` 2.152.14. Routes come from that release's oclif manifest,
including its flexible-taxonomy permutations and legacy `force:data` aliases.
Both executables published by the CLI, `sf` and `sfdx`, are covered.

| Rule | Routes | Native result |
| --- | --- | --- |
| `delete` | `data delete record`, `data delete bulk`, `force:data:record:delete`, `force:data:bulk:delete` | review |
| `update` | `data update record`, `data update bulk`, `data upsert bulk`, `force:data:record:update`, `force:data:bulk:upsert` | review |
| `create` | `data create record`, `data create file`, `data import bulk`, `data import tree`, `force:data:record:create`, `force:data:tree:import` | review |
| `export` | `data export bulk`, `data export tree`, `data bulk results`, `force:data:tree:export` | review |
| `resume` | `data delete/import/update/upsert/export resume` with a job ID | review |
| `resume-unbound` | the same resumes with `--use-most-recent` or `--flags-dir` | block |
| `hard-delete` | any `sf` invocation with `--hard-delete`, or a bulk delete with `--flags-dir` | block |

Starting a job and resuming one are separate rules, so a decision about a bulk
delete never covers its resume. A resume must name its job: `--use-most-recent`
picks whichever job ran last, so an earlier decision could land on a different
job. `--flags-dir` loads flag values from files that the command text does not
show, so it can add `--hard-delete` or `--use-most-recent`; it is blocked on bulk
deletes and resumes. `--flags-dir=<dir>` is detected the same way as the spaced form.

Reads emit no observation: `data query`, `data search`, `data get record`,
`data resume`, `force:data:soql:query`, `force:data:record:get` and
`force:data:bulk:status`. A query that writes to
`--output-file` is still a read of an org the CLI is already authorized for.
Help is not a safe variant here, so `--help` on a covered route is still reviewed.

The contribution does not resolve the target org. Without `--target-org`, the
CLI uses its configured default or an alias, and neither one is visible in the
command text. It also does not read the CSV file, query file or tree plan, so
it cannot bind a decision to the record set or field values. It does not count
records against a business budget either. Approval binding to the org, record
set and job identity remains native business-policy work. These fixtures do not
qualify any business mode.

Wrappers the native parser does not unwrap, other plugins (`project deploy`,
`apex run`, `org` commands), `npx @salesforce/cli` and mixed-colon forms in a
non-canonical order are outside this finite route list.

Canonical authoring inputs are the source JSON, the portable fixture and the
external trust binding. The preparation command generates the descriptor and
directory catalog projections; none are written by hand.
