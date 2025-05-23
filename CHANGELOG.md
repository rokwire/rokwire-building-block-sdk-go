# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Use notification message topic field [#44](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/44)

## [1.8.2] - 2025-05-21
- Fix hardcoded param in groups adapter - UpdateGroupDateUpdated api [#42](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/42)

## [1.8.1] - 2025-05-20
### Fixed
- Аdd type EventUsersResponse struct [#39](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/39)

## [1.8.0] - 2025-05-19
### Added
- Implement groups BB update date-updated callback API [#37](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/34)

## [1.7.0] - 2025-05-13
### Added
- Set GetEventUserIDs [#34](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/34)

## [1.6.1] - 2025-04-09
### Changed
- Upgrade go to v1.24.2, update dependencies

## [1.6.0] - 2024-02-14
## [1.5.0] - 2024-02-14
### Added 
- Add Org_apps_membership to the core account [#27](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/27)

### Fixed
- Fix Get user account to return the whole account [#20](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/20)
### Added
- Add CORS support [#22](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/22)

## [1.3.0] - 2024-12-09
### Added
- Find users from CoreBB [#18](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/18)

## [1.2.0] - 2024-11-14
### Added
- Implement get groups by ids adapter call [#16](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/16)

## [1.1.0] - 2024-11-09
### Added
- Add signature auth setup example [#14](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/14)
- Add Get group membership and Send notifications [#12](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/12)

## [1.0.2] - 2024-10-09
### Added
- BREAKING: Expose router for manual API definitions [#9](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/9)

## [1.0.1] - 2024-09-18
### Changed
- BREAKING: Upgrade dependencies [#6](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/6)
### Fixed
- Fix missing vendor API doc file issue

## [1.0.0] - 2024-07-30
### Changed
- Update existing packages [#1](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/1)

### Added
- Add common code from BB template [#3](https://github.com/rokwire/rokwire-building-block-sdk-go/issues/3)  
- Auth library
- Logging library

[Unreleased]: https://github.com/rokwire/rokwire-building-block-sdk-go/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/rokwire/rokwire-building-block-sdk-go/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/rokwire/rokwire-building-block-sdk-go/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/rokwire/rokwire-building-block-sdk-go/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/rokwire/rokwire-building-block-sdk-go/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/rokwire/rokwire-building-block-sdk-go/tree/v1.0.0