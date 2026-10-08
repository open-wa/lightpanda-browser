# OpenWA native session research

This fork preserves the native changes from the OpenWA / Lightpanda investigation on 7–8 October 2026. The implementation is on [codex/lightpanda-research](https://github.com/open-wa/lightpanda-browser/tree/codex/lightpanda-research), based on upstream commit e98a770e0ef37083b64e40d6047ab5fa5893cbff. It is an experimental derivative, not an official Lightpanda release.

Read the [complete sanitized research issue](https://github.com/open-wa/wa-automate-nodejs/issues/3517) for the measured stock benchmarks, authenticated startup and reload milestones, OpenWA integration corrections, related upstream sources, and unresolved reliability and delivery failures. The [OpenWA research branch](https://github.com/open-wa/wa-automate-nodejs/tree/codex/lightpanda-research) contains the driver and host integration.

The native changes include CryptoKey cloning, MessagePort and ArrayBuffer transfer, worker names, origin-scoped Web Locks, BufferSource handling, pending IndexedDB request-wrapper retention, DOMStringList iterator ownership, configured user-agent/client hints, and CacheStorage exposure independently of incomplete Service Workers. The implementation commit is [f984445bdc86563ad6236378197ded3da4b980f8](https://github.com/open-wa/lightpanda-browser/commit/f984445bdc86563ad6236378197ded3da4b980f8).

The [native patch instructions](https://github.com/open-wa/wa-automate-nodejs/blob/codex/lightpanda-research/packages/driver-lightpanda/native/README.md) describe executable selection and the research build target. The custom Debug build has not been resource-benchmarked. Reliable session recovery, outbound delivery, full synchronization, and Chrome feature parity remain unestablished; there is no Lightpanda Live Portal rendered feed.

No account data, session credentials, raw private diagnostics, or proprietary injected runtime source is included in this fork. Native changes retain the upstream AGPL-3.0-or-later license.
