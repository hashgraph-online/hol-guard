"""Explicit local benchmark entrypoint, independent of production CI/CD."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .campaign import compile_campaign
from .catalog import load_approval_variants, load_catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    profile = commands.add_parser('profile', help='export a bounded existing-contract beta selection; no inference')
    profile.add_argument('name', choices=['beta-e2e'])
    profile.add_argument('--output-dir', type=Path, required=True)
    deterministic = commands.add_parser('deterministic', help='run installed SDK/native controls without inference')
    deterministic.add_argument('--config', type=Path, required=True)
    deterministic.add_argument('--expected-config-digest', required=True)
    deterministic.add_argument('--asset-root', type=Path, required=True)
    deterministic.add_argument('--state-root', type=Path, required=True)
    deterministic.add_argument('--output-dir', type=Path, required=True)
    preview = commands.add_parser('preview', help='compile public inventory without inference')
    preview.add_argument('--seed', type=int, default=0)
    preview.add_argument('--output', type=Path)
    preview.add_argument('--authored-challenges', action='store_true',
                         help='include eight disclosed team-authored challenge instances')
    pilot = commands.add_parser('pilot', help='run one diagnostic live business episode')
    pilot.add_argument('--root', type=Path, required=True)
    pilot.add_argument('--workflow', required=True)
    pilot.add_argument('--challenge-id', help='declared authored instance of this business workflow')
    pilot.add_argument('--adapter', choices=['unprotected', 'example-policy', 'hol-guard'], default='unprotected')
    pilot.add_argument('--guard-python', type=Path)
    pilot.add_argument('--guard-source-sha')
    pilot.add_argument('--isolated', action='store_true',
                       help='use the owned Linux UID/namespace-isolated agent lane')
    pilot.add_argument('--product-isolated', action='store_true',
                       help='isolate HOL Guard as UID10004; requires --isolated')
    pilot.add_argument('--variant', default='clean',
                       help='clean or an attack variant declared by this fixture')
    pilot.add_argument('--bun', type=Path, required=True)
    pilot.add_argument('--sdk-root', type=Path, required=True)
    pilot.add_argument('--model-id', required=True)
    pilot.add_argument('--base-url', required=True)
    pilot.add_argument('--deadline-seconds', type=int, default=300)
    pilot.add_argument('--max-tool-calls', type=int, default=60)
    pilot.add_argument('--max-model-tokens', type=int, default=32_000)
    freeze = commands.add_parser('freeze', help='freeze an exact local selection and budget preview')
    freeze.add_argument('--root', type=Path, required=True)
    freeze.add_argument('--campaign', type=Path, required=True)
    freeze.add_argument('--selection', type=Path, required=True,
                        help='public JSON array of exact episode IDs')
    freeze.add_argument('--runtime', type=Path, required=True,
                        help='explicit public runtime/artifact JSON; no credentials')
    freeze.add_argument('--max-episodes', type=int, required=True)
    run = commands.add_parser('run', help='execute a previously frozen local selection')
    run.add_argument('--root', type=Path, required=True)
    run.add_argument('--preview-digest', required=True)
    status = commands.add_parser('status', help='audit frozen inputs and all retained attempts')
    status.add_argument('--root', type=Path, required=True)
    gate = commands.add_parser('gate', help='explicit local acceptance over audited retained evidence')
    gate.add_argument('--root', type=Path, required=True)
    gate.add_argument('--policy', type=Path, required=True)
    gate.add_argument('--expected-policy-digest', required=True)
    gate.add_argument('--expected-config-digest', required=True)
    gate.add_argument('--output-dir', type=Path, required=True)
    ci = commands.add_parser('ci', help='versioned portable local CI controller; no workflow activation')
    ci.add_argument('action', choices=['preflight', 'freeze', 'run', 'resume', 'report', 'check'])
    ci.add_argument('--config', type=Path, required=True)
    ci.add_argument('--expected-config-digest', required=True)
    ci.add_argument('--asset-root', type=Path, required=True)
    ci.add_argument('--state-root', type=Path)
    ci.add_argument('--expected-manifest-digest')
    ci.add_argument('--shard', type=int)
    ci.add_argument('--output-dir', type=Path, required=True)
    ci.add_argument('--profile', choices=['deterministic', 'beta-e2e', 'feature-ai', 'feature-ai-protocol'], default='deterministic',
                    help='ci check profile; live E2E must be explicitly selected')
    ci.add_argument('--expected-guard-source-sha',
                    help='ci check requires the externally supplied commit under test')
    approval = commands.add_parser('approval', help='run a two-session external approval diagnostic')
    approval.add_argument('args', nargs=argparse.REMAINDER)
    developer = commands.add_parser('developer', help='run an isolated developer diagnostic')
    developer.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command == 'deterministic':
        from .deterministic import main as deterministic_main
        return deterministic_main(args)
    if args.command == 'profile':
        from .beta_profile import export_profile
        print(json.dumps(export_profile(args.output_dir), indent=2))
        return 0
    if args.command == 'ci':
        if args.action == 'check':
            if args.state_root is None or not args.expected_guard_source_sha:
                parser.error('ci check requires --state-root and --expected-guard-source-sha')
            if args.expected_manifest_digest is not None or args.shard is not None:
                parser.error('ci check creates a fresh freeze and runs every declared shard')
            from .ci_pipeline import main as check_main
            return check_main(args)
        if args.profile != 'deterministic' or args.expected_guard_source_sha is not None:
            parser.error('--profile and --expected-guard-source-sha apply only to ci check')
        if args.action != 'preflight' and args.state_root is None:
            parser.error('ci freeze/run/resume/report requires --state-root')
        if args.action in {'run','resume','report'} and not args.expected_manifest_digest:
            parser.error('ci run/resume/report requires --expected-manifest-digest')
        if args.action in {'run','resume'} and args.shard is None:
            parser.error('ci run/resume requires --shard')
        from .ci_runner import main as ci_main
        return ci_main(args)
    if args.command == 'gate':
        from .ci_gate_report import run_gate
        return run_gate(args)
    if args.command == 'preview':
        provenance = 'public-base'
        export = None
        if args.authored_challenges:
            from .authored_challenges import compile_authored_campaign
            export = compile_authored_campaign(seed=args.seed)
            campaign = export['campaign']
            provenance = export['provenance']
        else:
            campaign = compile_campaign(load_catalog(), seed=args.seed,
                                        approval_variants=load_approval_variants())
        if args.output:
            with args.output.open('x', encoding='utf-8') as stream:
                json.dump(export or campaign, stream, indent=2)
                stream.write('\n')
        groups = dict(Counter(row['group'] for row in campaign['inventory']))
        if args.authored_challenges:
            groups['authored-challenge'] = groups.pop('holdout', 0)
        print(json.dumps({'id': campaign['id'], 'episodes': len(campaign['inventory']),
                          'provenance': provenance,
                          'groups': groups,
                          'qualification_eligible': False,
                          'qualification_reasons': campaign['qualification_reasons']}, indent=2))
        return 0
    if args.command in {'approval', 'developer'}:
        if args.command == 'approval':
            from .approval_pilot import main as diagnostic_main
        else:
            from .developer_pilot import main as diagnostic_main
        return diagnostic_main(args.args[1:] if args.args[:1] == ['--'] else args.args)
    if args.command in {'freeze', 'run', 'status'}:
        from .local_campaign import freeze_local_campaign, load_local_campaign, run_local_campaign
        if args.command == 'freeze':
            from .contracts import strict_json_loads
            inputs = [strict_json_loads(path.read_bytes()) for path in
                      (args.campaign, args.selection, args.runtime)]
            campaign, selection, runtime = inputs
            if isinstance(campaign, dict) and 'campaign' in campaign:
                campaign = campaign['campaign']
            result = freeze_local_campaign(args.root, campaign=campaign, episode_ids=selection,
                                           runtime=runtime, max_episodes=args.max_episodes)
        elif args.command == 'run':
            result = run_local_campaign(args.root, preview_digest=args.preview_digest)
        else:
            state = load_local_campaign(args.root)
            result = {'config_digest': state['config']['config_digest'],
                      'selected_episodes': len(state['config']['cells']),
                      'terminal_episodes': len(state['terminal_ids']),
                      'attempt_ledger_rows': len(state['ledger']), 'qualification_eligible': False}
        print(json.dumps(result, indent=2))
        return 0
    from .pilot import run_pilot
    report = run_pilot(root=args.root, workflow_id=args.workflow, variant=args.variant,
                       bun=args.bun, sdk_root=args.sdk_root, model_id=args.model_id,
                       base_url=args.base_url, deadline_seconds=args.deadline_seconds,
                       max_tool_calls=args.max_tool_calls, adapter_id=args.adapter,
                       challenge_id=args.challenge_id, max_model_tokens=args.max_model_tokens,
                       guard_python=args.guard_python, guard_source_sha=args.guard_source_sha,
                       isolated=args.isolated, product_isolated=args.product_isolated)
    print(json.dumps(report, indent=2))
    return 0 if report['execution_valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
