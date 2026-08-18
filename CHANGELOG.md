# Changelog

All notable changes to the Camellia Nexus Management Server will be recorded
here from the first commercial release onward.

## [1.1.1] - 2026-08-18

### Build

- update pnpm to 11.22.0 (#33)


### Fixed

- remediate management UI audit advisories (#32)


## [1.1.0] - 2026-08-10

### Added

- standardize shared-host Compose bootstrap (#25)


## [1.0.5] - 2026-08-09

### Fixed

- parameterize private production policy (#22)


## [1.0.4] - 2026-08-08

### Fixed

- isolate database credentials from process metadata


## [1.0.3] - 2026-08-08

### Fixed

- publish server as OCI-only release (#17)

- update nanoid security patch (#18)


## [1.0.2] - 2026-08-07

### Fixed

- grant worker lock columns and align dashboard timeline


## [1.0.1] - 2026-08-05

### Fixed

- reconcile completed publication lifecycle (#9)

- bind runtime checks to tag source (#10)

- reconcile incomplete registry aliases (#11)

- harden Nexus management runtime boundaries


## [1.0.0] - 2026-07-31

### Added

- establish Camellia Nexus management production baseline

- harden Nexus management for production (#5)

- freeze and verify service publication (#8)


### Changed

- randomize dummy credentials


### Fixed

- refresh pinned ClamAV LTS images (#7)


## [Unreleased]

- Establish the clean 0.1.0 pre-release service baseline.
- Adopt the Camellia proprietary authorization terms.
- Use the canonical `camellia.nexus.license` authorization scope.
- Squash all development-only PostgreSQL migrations into one clean baseline.
