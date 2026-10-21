//! Lower bounded graph operations without broadening the accepted grammar.
use super::*;

impl Builder<'_> {
    pub(super) fn operations(&mut self, code: &Code, analysis: Analysis) -> Result<String> {
        let mut replacements = BTreeMap::<(usize, usize), String>::new();
        let mut replacement_bytes = 0usize;
        let mut sources = analysis.sources;
        for operation in analysis.operations {
            self.expanded_bytes = self
                .expanded_bytes
                .saturating_add(operation.argv.iter().map(String::len).sum::<usize>());
            if self.expanded_bytes > MAX_SOURCE_BYTES {
                return Err(Uncertainty {
                    reason: "bash_expanded_data_bounds",
                    line: operation.line,
                });
            }
            if self.invocations.len() >= MAX_GRAPH_CALLS {
                return Err(Uncertainty {
                    reason: "bash_graph_bounds",
                    line: operation.line,
                });
            }
            let mut invocation = Invocation {
                source_path: code.original_path.clone(),
                operation: operation.clone(),
                resolved_path: None,
                broker_id: None,
            };
            let name = &operation.argv[0];
            let mut replacement_span = (operation.command_start, operation.command_end);
            let replacement = if matches!(name.as_str(), "source" | ".") {
                let index = sources
                    .iter()
                    .position(|source| source.command_start == operation.command_start)
                    .ok_or(Uncertainty {
                        reason: "bash_source_analysis_missing",
                        line: operation.line,
                    })?;
                let source = sources.remove(index);
                self.register(&source.code, inputs::Kind::Source)?;
                self.active.insert(source.code.resolved_path.clone());
                invocation.resolved_path = Some(source.code.resolved_path.clone());
                let empty = source.empty_program;
                let body = self.operations(&source.code, source.analysis)?;
                self.active.remove(&source.code.resolved_path);
                replacement_span = (source.start, source.end);
                Some(format!(
                    "{{\n{}{}\n}}",
                    if empty { ":\n" } else { "" },
                    body
                ))
            } else if matches!(
                name.as_str(),
                ":" | "printf" | "echo" | "set" | "test" | "[" | "exit" | "true" | "false"
            ) {
                None
            } else {
                let executable =
                    self.resolver
                        .resolve(&operation.argv)
                        .map_err(|reason| Uncertainty {
                            reason,
                            line: operation.line,
                        })?;
                match executable {
                    Executable::Native {
                        resolved_path,
                        content_sha256,
                        openssl_config,
                        delivery,
                    } => {
                        if !resolved_path.starts_with('/')
                            || resolved_path.len() > 4096
                            || resolved_path.contains('\0')
                            || content_sha256.len() != 64
                            || !content_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            return Err(Uncertainty {
                                reason: "bash_native_identity_invalid",
                                line: operation.line,
                            });
                        }
                        invocation.resolved_path = Some(resolved_path.clone());
                        let known = match delivery {
                            NativeDelivery::ReadonlySystem => {
                                self.native_images.contains_key(&resolved_path)
                            }
                            NativeDelivery::HardenedBroker => {
                                self.brokered_images.contains_key(&resolved_path)
                            }
                        };
                        if !known
                            && self.code.len()
                                + self.sources.len()
                                + self.startup.len()
                                + self.native_images.len()
                                + self.brokered_images.len()
                                + 1
                                >= MAX_CODE_INPUTS
                        {
                            return Err(Uncertainty {
                                reason: "bash_graph_bounds",
                                line: operation.line,
                            });
                        }
                        let images = match delivery {
                            NativeDelivery::ReadonlySystem => &mut self.native_images,
                            NativeDelivery::HardenedBroker => &mut self.brokered_images,
                        };
                        if images
                            .get(&resolved_path)
                            .is_some_and(|previous| previous != &content_sha256)
                        {
                            return Err(Uncertainty {
                                reason: "bash_code_changed_during_analysis",
                                line: operation.line,
                            });
                        }
                        images.insert(resolved_path.clone(), content_sha256);
                        if delivery == NativeDelivery::HardenedBroker {
                            if operation.pipeline_input {
                                let encoder_argv = vec!["/usr/bin/base64".to_owned()];
                                let encoder =
                                    self.resolver.resolve(&encoder_argv).map_err(|reason| {
                                        Uncertainty {
                                            reason,
                                            line: operation.line,
                                        }
                                    })?;
                                let Executable::Native {
                                    resolved_path: encoder_path,
                                    content_sha256: encoder_digest,
                                    openssl_config: None,
                                    delivery: NativeDelivery::ReadonlySystem,
                                } = encoder
                                else {
                                    return Err(Uncertainty {
                                        reason: "bash_broker_stdin_encoder_unproven",
                                        line: operation.line,
                                    });
                                };
                                if encoder_path != "/usr/bin/base64"
                                    || encoder_digest.len() != 64
                                    || !encoder_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                                {
                                    return Err(Uncertainty {
                                        reason: "bash_broker_stdin_encoder_unproven",
                                        line: operation.line,
                                    });
                                }
                                if !self.native_images.contains_key(&encoder_path)
                                    && self.code.len()
                                        + self.sources.len()
                                        + self.startup.len()
                                        + self.native_images.len()
                                        + self.brokered_images.len()
                                        + 1
                                        >= MAX_CODE_INPUTS
                                {
                                    return Err(Uncertainty {
                                        reason: "bash_graph_bounds",
                                        line: operation.line,
                                    });
                                }
                                if self
                                    .native_images
                                    .get(&encoder_path)
                                    .is_some_and(|previous| previous != &encoder_digest)
                                {
                                    return Err(Uncertainty {
                                        reason: "bash_code_changed_during_analysis",
                                        line: operation.line,
                                    });
                                }
                                self.native_images.insert(encoder_path, encoder_digest);
                            }
                            if openssl_config.is_some() {
                                return Err(Uncertainty {
                                    reason: "bash_broker_startup_unproven",
                                    line: operation.line,
                                });
                            }
                            // The wire ID identifies the immutable source call site.
                            // Literal loop iterations can have different analyzed argv,
                            // while the native plan still binds each exact invocation in
                            // order. A per-argv ID would make one frozen source span
                            // context-dependent and therefore impossible to render.
                            let key = (
                                code.resolved_path.clone(),
                                operation.command_start,
                                operation.command_end,
                            );
                            let next =
                                u16::try_from(self.broker_ids.len()).map_err(|_| Uncertainty {
                                    reason: "bash_broker_invocation_bounds",
                                    line: operation.line,
                                })?;
                            let id = *self.broker_ids.entry(key).or_insert(next);
                            invocation.broker_id = Some(id);
                            Some(format!(
                                "__guard_broker_call {id} {}",
                                u8::from(operation.pipeline_input)
                            ))
                        } else {
                            // Keep the original native argv[0] while pinning the
                            // executable path. A direct path replacement changes it.
                            let mut launch =
                                format!("exec -a \"$0\" {} \"$@\"", quote(&resolved_path));
                            if let Some(config) = openssl_config {
                                launch =
                                    self.curl_startup(&operation, &resolved_path, config, launch)?;
                            }
                            Some(format!(
                                "/bin/bash --noprofile --norc -c {} {}",
                                quote(&launch),
                                quote(name)
                            ))
                        }
                    }
                    Executable::Bash(helper) => {
                        invocation.resolved_path = Some(helper.resolved_path.clone());
                        let mut helper_argv = operation.argv.clone();
                        helper_argv[0] = helper.original_path.clone();
                        let frozen = self.visit(&helper, &helper_argv)?;
                        if frozen.len() > broker::MAX_HELPER_ARGUMENT_BYTES {
                            return Err(Uncertainty {
                                reason: "bash_helper_delivery_bounds",
                                line: operation.line,
                            });
                        }
                        // This closure uses Bash's protected system interpreter.
                        // The native backend must verify that assurance, enforce
                        // the argv size and attach the reviewed effect boundary.
                        let encoded = quote(&frozen);
                        if encoded.len() > broker::MAX_HELPER_ARGUMENT_BYTES {
                            return Err(Uncertainty {
                                reason: "bash_helper_delivery_bounds",
                                line: operation.line,
                            });
                        }
                        Some(format!(
                            "/bin/bash --noprofile --norc -c {} {}",
                            encoded,
                            quote(&helper.original_path)
                        ))
                    }
                }
            };
            if self.invocations.len() >= MAX_GRAPH_CALLS {
                return Err(Uncertainty {
                    reason: "bash_graph_bounds",
                    line: operation.line,
                });
            }
            self.invocations.push(invocation);
            if let Some(replacement) = replacement {
                let span = replacement_span;
                if replacements
                    .get(&span)
                    .is_some_and(|previous| previous != &replacement)
                {
                    // Different loop iterations may select different helper
                    // branches. Their source still must freeze identically.
                    return Err(Uncertainty {
                        reason: "bash_context_dependent_rewrite",
                        line: operation.line,
                    });
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = replacements.entry(span)
                {
                    replacement_bytes += replacement.len();
                    if replacement_bytes + code.source.len() > MAX_RENDERED_BYTES {
                        return Err(Uncertainty {
                            reason: "bash_rendered_source_bounds",
                            line: operation.line,
                        });
                    }
                    entry.insert(replacement);
                }
            }
        }
        for redirect in analysis.writes {
            if let Some(outputs) = self.output_fds {
                let fd = outputs.get(&redirect.path).ok_or(Uncertainty {
                    reason: "bash_output_handle_missing",
                    line: redirect.line,
                })?;
                let replacement = format!(">&{fd}");
                let span = (redirect.start, redirect.end);
                if replacements
                    .get(&span)
                    .is_some_and(|previous| previous != &replacement)
                {
                    return Err(Uncertainty {
                        reason: "bash_context_dependent_output",
                        line: redirect.line,
                    });
                }
                replacements.insert(span, replacement);
            }
            self.writes.push(OutputEffect {
                source_path: code.original_path.clone(),
                redirect,
            });
        }
        let mut source = code.source.to_string();
        for ((start, end), replacement) in replacements.into_iter().rev() {
            source.replace_range(start..end, &replacement);
        }
        if source.len() > MAX_RENDERED_BYTES {
            return Err(Uncertainty {
                reason: "bash_rendered_source_bounds",
                line: 1,
            });
        }
        Ok(source)
    }
}
