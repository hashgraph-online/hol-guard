# HOL Guard MDM Cloud hardening TODO

Status: 336 implementation tasks complete; 24 native/provider certification gates remain.

## Control contracts

- [x] MDM-001 Define canonical JSON.
- [x] MDM-002 Bound request bytes.
- [x] MDM-003 Reject duplicate keys.
- [x] MDM-004 Reject unknown fields.
- [x] MDM-005 Limit nesting depth.
- [x] MDM-006 Limit collection size.
- [x] MDM-007 Limit string size.
- [x] MDM-008 Validate identifiers.
- [x] MDM-009 Validate generations.
- [x] MDM-010 Validate timestamps.
- [x] MDM-011 Validate policy hashes.
- [x] MDM-012 Bind workspace.
- [x] MDM-013 Bind device.
- [x] MDM-014 Bind generation.
- [x] MDM-015 Document errors.

## Device identity

- [x] MDM-016 Generate P-256 key.
- [x] MDM-017 Persist private key.
- [x] MDM-018 Pin Cloud key.
- [x] MDM-019 Hash public key id.
- [x] MDM-020 Use one-time enrollment.
- [x] MDM-021 Reject token reuse.
- [x] MDM-022 Reject key cloning.
- [x] MDM-023 Reject identity collision.
- [x] MDM-024 Bind request method.
- [x] MDM-025 Bind request path.
- [x] MDM-026 Bind request body.
- [x] MDM-027 Require request time.
- [x] MDM-028 Require monotonic sequence.
- [x] MDM-029 Reject proof replay.
- [x] MDM-030 Test clock skew.

## Signed configuration

- [x] MDM-031 Generate RSA key.
- [x] MDM-032 Persist signing key.
- [x] MDM-033 Use RSA-PSS SHA-256.
- [x] MDM-034 Sign exact envelope.
- [x] MDM-035 Verify exact envelope.
- [x] MDM-036 Bind policy hash.
- [x] MDM-037 Bind predecessor hash.
- [x] MDM-038 Require monotonic revision.
- [x] MDM-039 Support skipped revisions.
- [x] MDM-040 Scope assignment per device.
- [x] MDM-041 Use bounded validity.
- [x] MDM-042 Reject expired config.
- [x] MDM-043 Reject future config.
- [x] MDM-044 Reject bad signature.
- [x] MDM-045 Reject stale replay.

## Policy application

- [x] MDM-046 Call managed parser.
- [x] MDM-047 Write policy atomically.
- [x] MDM-048 Use restrictive permissions.
- [x] MDM-049 Persist pending checkpoint.
- [x] MDM-050 Recover interrupted apply.
- [x] MDM-051 Persist revision checkpoint.
- [x] MDM-052 Persist policy hash.
- [x] MDM-053 Queue acknowledgement.
- [x] MDM-054 Flush acknowledgement.
- [x] MDM-055 Retain last good policy.
- [x] MDM-056 Fail closed on corruption.
- [x] MDM-057 Fail closed on chain break.
- [x] MDM-058 Handle 204 no policy.
- [x] MDM-059 Handle 304 unchanged.
- [x] MDM-060 Test rollback policy.

## Cloud durability

- [x] MDM-061 Use SQLite state.
- [x] MDM-062 Enable WAL mode.
- [x] MDM-063 Use FULL sync.
- [x] MDM-064 Create idempotent schema.
- [x] MDM-065 Persist device rows.
- [x] MDM-066 Persist assignments.
- [x] MDM-067 Persist policy history.
- [x] MDM-068 Persist acknowledgements.
- [x] MDM-069 Persist health reports.
- [x] MDM-070 Persist remediation jobs.
- [x] MDM-071 Persist audit events.
- [x] MDM-072 Serialize writes.
- [x] MDM-073 Use unique constraints.
- [x] MDM-074 Recover after restart.
- [x] MDM-075 Test database reuse.

## Fleet rollout

- [x] MDM-076 Publish baseline.
- [x] MDM-077 Target all devices.
- [x] MDM-078 Target canary device.
- [x] MDM-079 Preserve non-canary state.
- [x] MDM-080 Advance canary revision.
- [x] MDM-081 Record per-device predecessor.
- [x] MDM-082 Support skipped revisions.
- [x] MDM-083 Detect publish unknown device.
- [x] MDM-084 Publish signed rollback.
- [x] MDM-085 Require rollback reason.
- [x] MDM-086 Keep revision monotonic.
- [x] MDM-087 Confirm final convergence.
- [x] MDM-088 Expose assignment state.
- [x] MDM-089 Test partial rollout.
- [x] MDM-090 Test retry after failure.

## Acknowledgements

- [x] MDM-091 Define ack schema.
- [x] MDM-092 Bind ack workspace.
- [x] MDM-093 Bind ack device.
- [x] MDM-094 Bind ack generation.
- [x] MDM-095 Bind ack revision.
- [x] MDM-096 Bind ack policy hash.
- [x] MDM-097 Validate ack status.
- [x] MDM-098 Require rejection reason.
- [x] MDM-099 Forbid applied reason.
- [x] MDM-100 Use request id.
- [x] MDM-101 Deduplicate ack.
- [x] MDM-102 Persist before response.
- [x] MDM-103 Reject mismatched assignment.
- [x] MDM-104 Audit acknowledgement.
- [x] MDM-105 Test lost response retry.

## Health reporting

- [x] MDM-106 Define health schema.
- [x] MDM-107 Bind health workspace.
- [x] MDM-108 Bind health device.
- [x] MDM-109 Bind health generation.
- [x] MDM-110 Require sequence.
- [x] MDM-111 Reject sequence replay.
- [x] MDM-112 Bind applied revision.
- [x] MDM-113 Bind applied hash.
- [x] MDM-114 Allow pre-policy health.
- [x] MDM-115 Bound status object.
- [x] MDM-116 Reject authority fields.
- [x] MDM-117 Persist health.
- [x] MDM-118 Audit health.
- [x] MDM-119 Queue offline health.
- [x] MDM-120 Test monotonic recovery.

## Remediation

- [x] MDM-121 Define fixed actions.
- [x] MDM-122 Reject arbitrary shell.
- [x] MDM-123 Reject scripts.
- [x] MDM-124 Reject command fields.
- [x] MDM-125 Bind remediation identity.
- [x] MDM-126 Require job id.
- [x] MDM-127 Require idempotency key.
- [x] MDM-128 Bound validity.
- [x] MDM-129 Bound attempts.
- [x] MDM-130 Validate repair scope.
- [x] MDM-131 Validate service name.
- [x] MDM-132 Validate target version.
- [x] MDM-133 Persist result.
- [x] MDM-134 Deduplicate job.
- [x] MDM-135 Audit lifecycle.

## Fault injection

- [x] MDM-136 Add partition fault.
- [x] MDM-137 Add delay fault.
- [x] MDM-138 Add forced status.
- [x] MDM-139 Add dropped connection.
- [x] MDM-140 Add config corruption.
- [x] MDM-141 Add response truncation.
- [x] MDM-142 Add stale replay.
- [x] MDM-143 Add ETag stripping.
- [x] MDM-144 Scope faults per device.
- [x] MDM-145 Make one-shot faults.
- [x] MDM-146 Expose reset endpoint.
- [x] MDM-147 Protect admin endpoint.
- [x] MDM-148 Bound fault values.
- [x] MDM-149 Retain response history.
- [x] MDM-150 Test each fault.

## Device process

- [x] MDM-151 Expose health endpoint.
- [x] MDM-152 Expose sync endpoint.
- [x] MDM-153 Expose state endpoint.
- [x] MDM-154 Protect fault surface.
- [x] MDM-155 Persist metadata.
- [x] MDM-156 Persist outboxes.
- [x] MDM-157 Persist proofs.
- [x] MDM-158 Increment sequence pre-send.
- [x] MDM-159 Flush acks first.
- [x] MDM-160 Flush health first.
- [x] MDM-161 Poll remediation.
- [x] MDM-162 Recover pending apply.
- [x] MDM-163 Report bounded state.
- [x] MDM-164 Use independent volume.
- [x] MDM-165 Test three processes.

## Cloud process

- [x] MDM-166 Expose health endpoint.
- [x] MDM-167 Protect admin routes.
- [x] MDM-168 Expose publish route.
- [x] MDM-169 Expose remediation route.
- [x] MDM-170 Expose state route.
- [x] MDM-171 Expose enrollment route.
- [x] MDM-172 Expose config route.
- [x] MDM-173 Expose ack route.
- [x] MDM-174 Expose health route.
- [x] MDM-175 Expose remediation poll.
- [x] MDM-176 Expose result route.
- [x] MDM-177 Return no-store headers.
- [x] MDM-178 Return ETag.
- [x] MDM-179 Bound request body.
- [x] MDM-180 Map contract errors.

## Docker isolation

- [x] MDM-181 Use internal network.
- [x] MDM-182 Expose no host ports.
- [x] MDM-183 Drop Linux capabilities.
- [x] MDM-184 Set no-new-privileges.
- [x] MDM-185 Use read-only rootfs.
- [x] MDM-186 Use tmpfs for temp.
- [x] MDM-187 Use separate state volumes.
- [x] MDM-188 Use healthchecks.
- [x] MDM-189 Gate dependencies.
- [x] MDM-190 Set memory limits.
- [x] MDM-191 Set CPU limits.
- [x] MDM-192 Avoid Docker socket.
- [x] MDM-193 Use locked dependencies.
- [x] MDM-194 Build current worktree.
- [x] MDM-195 Tear down volumes.

## Orchestration

- [x] MDM-196 Enroll three devices.
- [x] MDM-197 Publish baseline.
- [x] MDM-198 Apply baseline.
- [x] MDM-199 Publish canary.
- [x] MDM-200 Assert canary only.
- [x] MDM-201 Corrupt configuration.
- [x] MDM-202 Assert fail closed.
- [x] MDM-203 Recover valid retry.
- [x] MDM-204 Partition device.
- [x] MDM-205 Assert local continuity.
- [x] MDM-206 Recover partition.
- [x] MDM-207 Replay proof.
- [x] MDM-208 Substitute workspace.
- [x] MDM-209 Replay old config.
- [x] MDM-210 Execute rollback.

## Crash recovery

- [x] MDM-211 Inject crash after write.
- [x] MDM-212 Persist pending record.
- [x] MDM-213 Retain policy file.
- [x] MDM-214 Recover checkpoint.
- [x] MDM-215 Recover acknowledgement.
- [x] MDM-216 Flush outbox.
- [x] MDM-217 Avoid duplicate apply.
- [x] MDM-218 Retain request sequence.
- [x] MDM-219 Retain health sequence.
- [x] MDM-220 Handle restart.
- [x] MDM-221 Handle missing checkpoint.
- [x] MDM-222 Handle mismatched pending hash.
- [x] MDM-223 Remove corrupt pending.
- [x] MDM-224 Verify atomic rename.
- [x] MDM-225 Test durable convergence.

## Concurrency

- [x] MDM-226 Serialize enrollment.
- [x] MDM-227 Serialize request sequence.
- [x] MDM-228 Serialize publication.
- [x] MDM-229 Use transaction boundaries.
- [x] MDM-230 Use uniqueness constraints.
- [x] MDM-231 Handle duplicate enroll.
- [x] MDM-232 Handle duplicate ack.
- [x] MDM-233 Handle duplicate health.
- [x] MDM-234 Handle duplicate job.
- [x] MDM-235 Handle parallel sync.
- [x] MDM-236 Handle publish during sync.
- [x] MDM-237 Handle retry storms.
- [x] MDM-238 Bound HTTP timeout.
- [x] MDM-239 Use threaded servers.
- [x] MDM-240 Test deterministic order.

## Privacy

- [x] MDM-241 Never store enrollment token.
- [x] MDM-242 Hash enrollment token.
- [x] MDM-243 Exclude private keys.
- [x] MDM-244 Exclude bearer tokens.
- [x] MDM-245 Exclude proxy credentials.
- [x] MDM-246 Exclude commands.
- [x] MDM-247 Redact audit detail.
- [x] MDM-248 Bound error detail.
- [x] MDM-249 Bound report evidence.
- [x] MDM-250 Avoid user paths.
- [x] MDM-251 Avoid network addresses.
- [x] MDM-252 Avoid environment dump.
- [x] MDM-253 Avoid response secrets.
- [x] MDM-254 Scan serialized state.
- [x] MDM-255 Test redaction.

## Observability

- [x] MDM-256 Emit canonical report.
- [x] MDM-257 Include step names.
- [x] MDM-258 Include pass state.
- [x] MDM-259 Include bounded evidence.
- [x] MDM-260 Include step count.
- [x] MDM-261 Include generated time.
- [x] MDM-262 Include workspace.
- [x] MDM-263 Include native boundary.
- [x] MDM-264 Expose Cloud state.
- [x] MDM-265 Expose device state.
- [x] MDM-266 Record audit time.
- [x] MDM-267 Record assignment revision.
- [x] MDM-268 Record health sequence.
- [x] MDM-269 Record job status.
- [x] MDM-270 Upload CI artifact.

## Schemas

- [x] MDM-271 Add config schema.
- [x] MDM-272 Add ack schema.
- [x] MDM-273 Add health schema.
- [x] MDM-274 Add remediation schema.
- [x] MDM-275 Add enrollment schema.
- [x] MDM-276 Add report schema.
- [x] MDM-277 Use draft 2020-12.
- [x] MDM-278 Disallow extra fields.
- [x] MDM-279 Constrain identifiers.
- [x] MDM-280 Constrain generations.
- [x] MDM-281 Constrain hashes.
- [x] MDM-282 Constrain timestamps.
- [x] MDM-283 Constrain actions.
- [x] MDM-284 Validate examples.
- [x] MDM-285 Reject authority fields.

## Automated tests

- [x] MDM-286 Test signatures.
- [x] MDM-287 Test tampering.
- [x] MDM-288 Test binding.
- [x] MDM-289 Test chain mismatch.
- [x] MDM-290 Test revision replay.
- [x] MDM-291 Test proof path binding.
- [x] MDM-292 Test proof body binding.
- [x] MDM-293 Test proof sequence.
- [x] MDM-294 Test ack strictness.
- [x] MDM-295 Test health strictness.
- [x] MDM-296 Test remediation strictness.
- [x] MDM-297 Test schema validity.
- [x] MDM-298 Test real HTTP stack.
- [x] MDM-299 Test report artifact.
- [x] MDM-300 Test native disclaimer.

## CI integration

- [x] MDM-301 Add focused workflow.
- [x] MDM-302 Pin checkout action.
- [x] MDM-303 Pin Python action.
- [x] MDM-304 Pin uv action.
- [x] MDM-305 Pin artifact action.
- [x] MDM-306 Use Python 3.12.
- [x] MDM-307 Use locked uv sync.
- [x] MDM-308 Run focused tests.
- [x] MDM-309 Run Docker lab.
- [x] MDM-310 Validate report.
- [x] MDM-311 Collect failure logs.
- [x] MDM-312 Upload evidence.
- [x] MDM-313 Always teardown.
- [x] MDM-314 Use concurrency group.
- [x] MDM-315 Limit timeout.

## Documentation

- [x] MDM-316 Write PRD.
- [x] MDM-317 Write task ledger.
- [x] MDM-318 Write takeaway prompt.
- [x] MDM-319 Document architecture.
- [x] MDM-320 Document trust model.
- [x] MDM-321 Document threat model.
- [x] MDM-322 Document scenarios.
- [x] MDM-323 Document operations.
- [x] MDM-324 Document local command.
- [x] MDM-325 Document Docker command.
- [x] MDM-326 Document fast tests.
- [x] MDM-327 Document regression steps.
- [x] MDM-328 Document limitations.
- [x] MDM-329 Document native gates.
- [x] MDM-330 Document evidence format.

## Release evidence

- [x] MDM-331 Compile Python modules.
- [x] MDM-332 Parse Compose YAML.
- [x] MDM-333 Parse JSON schemas.
- [x] MDM-334 Run contract tests.
- [x] MDM-335 Run real HTTP integration.
- [x] MDM-336 Package bounded evidence.

## Native and provider certification

- [ ] MDM-337 Validate Apple APNs enrollment.
- [ ] MDM-338 Validate Apple supervision.
- [ ] MDM-339 Validate Automated Device Enrollment.
- [ ] MDM-340 Validate declarative management activation.
- [ ] MDM-341 Validate macOS profile removal.
- [ ] MDM-342 Validate signed macOS package.
- [ ] MDM-343 Validate macOS notarization.
- [ ] MDM-344 Validate Secure Enclave key behavior.
- [ ] MDM-345 Validate Windows CSP enrollment.
- [ ] MDM-346 Validate Windows SYSTEM context.
- [ ] MDM-347 Validate SyncML replacement flow.
- [ ] MDM-348 Validate Windows policy registry ACLs.
- [ ] MDM-349 Validate Authenticode signatures.
- [ ] MDM-350 Validate WDAC interaction.
- [ ] MDM-351 Validate Intune Win32 deployment.
- [ ] MDM-352 Validate Intune remediation scheduling.
- [ ] MDM-353 Validate Jamf policy ordering.
- [ ] MDM-354 Validate Kandji Library Item delivery.
- [ ] MDM-355 Validate Workspace ONE assignment.
- [ ] MDM-356 Validate real vendor retries.
- [ ] MDM-357 Validate real vendor duplicate delivery.
- [ ] MDM-358 Validate production proxy interception.
- [ ] MDM-359 Validate production private CA chain.
- [ ] MDM-360 Validate provider RBAC audit export.
