//! Read-only system image acquisition and applicable startup configuration.
use super::*;

impl Resolver<'_> {
    pub(super) fn image(&self, path: &Path) -> Result<PinnedCommand> {
        self.check()?;
        let pinned = PinnedCommand::new(path, &[], self.cwd, &[])
            .map_err(|_| "bash_system_image_unavailable")?;
        if !pinned
            .has_readonly_system_image()
            .map_err(|_| "bash_system_image_unavailable")?
        {
            return Err("bash_system_image_not_immutable");
        }
        self.check()?;
        Ok(pinned)
    }
}

pub(super) fn capture(resolver: &Resolver<'_>, path: &Path) -> Result<graph::Executable> {
    let pinned = resolver.image(path)?;
    let openssl_config = if path == Path::new("/usr/bin/curl") {
        super::super::super::bash_curl_backend::verify(&pinned, resolver.cwd, resolver.deadline)?;
        let config = "/private/etc/ssl/openssl.cnf";
        Some(resolver.code(config, &canonical(config)?)?)
    } else {
        None
    };
    Ok(graph::Executable::Native {
        resolved_path: text(path)?,
        content_sha256: pinned.executable_digest,
        openssl_config,
        delivery: graph::NativeDelivery::ReadonlySystem,
    })
}

pub(super) fn capture_hardened(
    resolver: &Resolver<'_>,
    path: &Path,
    argv: &[String],
) -> Result<(graph::Executable, PinnedCommand)> {
    let arguments = argv[1..]
        .iter()
        .map(std::ffi::OsStr::new)
        .collect::<Vec<_>>();
    let environment = resolver
        .environment
        .iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<Vec<_>>();
    let command = PinnedCommand::new(path, &arguments, resolver.cwd, &environment)
        .and_then(|command| {
            command.with_invocation_argv0(std::ffi::OsStr::new(&argv[0]), &arguments, &environment)
        })
        .map_err(|_| "bash_hardened_image_unavailable")?;
    if command
        .has_readonly_system_image()
        .map_err(|_| "bash_hardened_image_unavailable")?
    {
        return Err("bash_hardened_system_image_unmodeled");
    }
    command
        .verify_hardened_image()
        .map_err(|_| "bash_hardened_image_unavailable")?;
    Ok((
        graph::Executable::Native {
            resolved_path: text(path)?,
            content_sha256: command.executable_digest.clone(),
            openssl_config: None,
            delivery: graph::NativeDelivery::HardenedBroker,
        },
        command,
    ))
}
