use super::*;

pub(super) fn prove(
    model: &CanonicalCommandV1,
    context: super::super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(add) = worktree_index(model) else {
        return false;
    };
    let segments = &model.segments;
    let entry = leading::leading_entry(model, context);
    let start = usize::from(entry.is_some());
    if add < start {
        return false;
    }
    let context = super::super::super::PathContext {
        cwd: entry.as_deref().or(context.cwd),
        ..context
    };
    // `git fetch origin main && git worktree add ... origin/main` refreshes
    // the start point first; the worktree proof then admits only the
    // standard LFS filter, since the fetched tree is not the one it read.
    let mut fetch_before = false;
    for segment in &segments[start..add] {
        let proven = if segment.pipeline_index == 0 {
            super::super::super::git_remote_ops::proven_fetch(
                segment,
                context,
                deadline,
                execution_environment,
            )
        } else {
            super::super::chain_route::stdin_stage(segment, context, execution_environment)
        };
        if !proven {
            return false;
        }
        fetch_before = true;
    }
    let creation = &segments[add];
    let after = after_creation(model, add);
    let Some(next) = segments.get(after) else {
        return false;
    };
    if creation.pipeline_index != 0 || next.pipeline_index != 0 {
        return false;
    }
    if !segments[add + 1..after].iter().all(|segment| {
        super::super::chain_route::stdin_stage(segment, context, execution_environment)
    }) {
        return false;
    }
    let entered = next.executable.as_deref() == Some("cd");
    let linked = next.executable.as_deref() == Some("ln");
    let boundary = super::super::separator_between(model, after - 1, after);
    // `&&` straight after the add tests the add's own exit status, so the
    // checkout is there before anything reads it. A stage of the add's own
    // pipeline reports its status instead, and `;` reports none, so those
    // spellings prove the add ran only through the `cd`: the checkout proof
    // read the destination and found nothing there, so entering it succeeds
    // only once the add has created it, and a failed `cd` stops the `&&`
    // that carries the reads. An `ln` into the checkout fails the same way
    // while the checkout is not there, and its `&&` carries the rest.
    let joined = match boundary.as_deref().map(str::trim) {
        Some("&&") => after == add + 1 || entered || linked,
        Some(";") => entered,
        _ => false,
    };
    if !joined {
        return false;
    }
    let Some((destination, chdir, commit)) = super::super::proven_checkout(
        creation,
        fetch_before,
        context,
        deadline,
        execution_environment,
    ) else {
        return false;
    };
    if entered && super::super::chain_route::cd_target(next, context).as_ref() != Some(&destination)
    {
        return false;
    }
    // After the `cd` the shell looks every program up again, `git` among
    // them, so a search path entry inside the new checkout decides what the
    // chain's own reads run. The add refuses an existing destination, so
    // nothing but the ref it checks out fills such an entry.
    //
    // A chain that routes its steps with `git -C <checkout>` reaches the
    // same directory without entering it, and looks `git` up on the same
    // search path, so it answers for the same entry. Its own directory does
    // not move, which is what lets a relative entry be read here at all.
    let screened = if entered {
        super::super::search_path::search_path_outside(&destination, execution_environment)
    } else {
        super::super::search_path::routed_search_path_outside(
            &destination,
            context.cwd.map(std::path::Path::new),
            execution_environment,
        )
    };
    if !screened {
        return false;
    }
    // Reads are proven in the repository the checkout belongs to. If the
    // `cd` fails, a read after `;` runs in the shell's own directory, so `;`
    // is accepted only when that directory is the proven repository. A
    // routed read has no such fallback: after a failed add, `-C` could enter
    // a directory someone else made in the meantime.
    let fallback_proven = entered && (chdir.is_none() || chdir.as_deref() == context.cwd);
    let repository = super::super::super::PathContext {
        cwd: chdir.as_deref().or(context.cwd),
        ..context
    };
    let first = if entered { after + 1 } else { after };
    // Without a `cd` the chain must read or link into the new checkout: an
    // add followed only by `mkdir` keeps the review work-tree updates give
    // later writes.
    if !entered
        && !segments[first..]
            .iter()
            .any(|segment| matches!(segment.executable.as_deref(), Some("git" | "ln")))
    {
        return false;
    }
    // A step that only prints rides along a chain whose Git reads carry the
    // proof. On its own it reads nothing of the new checkout, so entering
    // the checkout and then only listing it keeps the review it had.
    let reads_git = segments[first..].iter().any(|segment| {
        let name = segment
            .executable
            .as_deref()
            .map(super::super::super::executable_basename);
        segment.pipeline_index == 0 && matches!(name, Some("git" | "gh"))
    });
    let mut links = Vec::new();
    (first..segments.len()).all(|index| {
        let joined = super::super::separator_between(model, index - 1, index);
        if !joined
            .as_deref()
            .is_some_and(|separator| match separator.trim() {
                "&&" | "|" => true,
                ";" => fallback_proven,
                _ => false,
            })
        {
            return false;
        }
        let segment = &segments[index];
        if segment.pipeline_index > 0 {
            return super::super::chain_route::stdin_stage(
                segment,
                repository,
                execution_environment,
            );
        }
        if entered {
            if super::super::chain_route::unrouted_read(
                model,
                index,
                repository,
                deadline,
                execution_environment,
            ) {
                return true;
            }
            // The branch the chain creates in the checkout it just made.
            if super::super::chain_route::new_branch_step(segment) {
                return true;
            }
            return reads_git
                && super::super::chain_route::inert_step(segment)
                && super::super::chain_route::resolved_outside(segment, &destination);
        }
        if segment.executable.as_deref() == Some("mkdir") {
            return super::super::chain_route::proven_mkdir(segment, &destination, context);
        }
        if segment.executable.as_deref() == Some("ln") {
            return super::super::links::proven_link(
                segment,
                creation,
                &destination,
                commit.as_deref(),
                context,
                repository,
                deadline,
                execution_environment,
            )
            .is_some_and(|link| super::super::links::record_link(&mut links, link));
        }
        if super::super::links::listing_through_links(segment, &links, &destination, context) {
            return true;
        }
        routed_step(
            model,
            index,
            context,
            repository,
            deadline,
            execution_environment,
        )
    })
}
