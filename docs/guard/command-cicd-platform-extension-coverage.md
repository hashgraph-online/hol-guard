# CI/CD and Platform Command Extension Coverage

Guard evaluates remote pipeline and hosting operations from the canonical parsed command model. Rules match executable, subcommand, and flag structure while preserving documented preview and help variants.

## Extensions

| Extension | Reviewed operations | Safe counterparts |
| --- | --- | --- |
| `command.cicd.github` | Cancel or delete workflow runs; disable workflows | Help, run view, workflow view |
| `command.cicd.gitlab` | Cancel one or more pipelines | Dry run, help |
| `command.cicd.circleci` | Start a remote pipeline | Help, local configuration validation |
| `command.platform.vercel` | Remove deployments or projects; deploy, promote, or roll back production | Help, project inspection, promotion status |
| `command.platform.netlify` | Delete sites; deploy to production | Help, draft deploys, dry builds |
| `command.platform.heroku` | Destroy apps; promote pipelines; roll back releases | Help, app and release inspection |

Global repository, account, team, site, app, host, and authentication options are normalized wherever the CLI accepts them. Reordered operation flags and native Windows launcher suffixes use the same rules.

## References

- [GitHub CLI run cancel](https://cli.github.com/manual/gh_run_cancel)
- [GitHub CLI run delete](https://cli.github.com/manual/gh_run_delete)
- [GitHub CLI workflow disable](https://cli.github.com/manual/gh_workflow_disable)
- [GitLab CLI cancel pipeline](https://docs.gitlab.com/cli/ci/cancel/pipeline/)
- [CircleCI pipeline management](https://circleci.com/docs/guides/toolkit/how-to-use-the-circleci-local-cli/)
- [Vercel CLI](https://vercel.com/docs/cli)
- [Netlify CLI guide](https://docs.netlify.com/api-and-cli-guides/cli-guides/get-started-with-cli/)
- [Heroku CLI commands](https://devcenter.heroku.com/articles/heroku-cli-commands)
- [Heroku pipelines](https://devcenter.heroku.com/articles/pipelines)
