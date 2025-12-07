# Changelog

## 1.0.0 (2025-12-07)


### ⚠ BREAKING CHANGES

* **windows:** None - all changes are backward compatible with WMIC fallback

### Features

* scanner improvements with CI/CD pipeline ([7a3b304](https://github.com/sosalejandro/sentinelguard/commit/7a3b30425cf8c13587fe66f56e8c372caf472e4a))
* **scanner:** add context cancellation, Windows support, and unit tests ([830c4ff](https://github.com/sosalejandro/sentinelguard/commit/830c4ff3312043ac6221d2b1941a2b63992c1d7e))
* **scanner:** improve SSH, PAM, and network scanning accuracy ([679b57d](https://github.com/sosalejandro/sentinelguard/commit/679b57d3e204af4975b517c0915639e87dec802b))


### Bug Fixes

* **core:** add thread-safety, panic recovery, and deterministic ordering ([6adaa88](https://github.com/sosalejandro/sentinelguard/commit/6adaa888fa5678561f8acfaa3d47acf38556ecdd))
* resolve all golangci-lint errors ([53ff099](https://github.com/sosalejandro/sentinelguard/commit/53ff099cfd15dbf5a457301e36998d49d376665d))
* **scanner:** add Category() to interface and fix correctness issues ([18b8314](https://github.com/sosalejandro/sentinelguard/commit/18b8314795e407d138fc7ad4f0cb4bb9f9259a79))
* **scanner:** address critical cross-platform and detection gaps ([5d89f14](https://github.com/sosalejandro/sentinelguard/commit/5d89f14ee7de7b48c1585ae5f9ca8e95eb00f21b))
* **windows:** address critical gaps in Windows security scanning ([5391ece](https://github.com/sosalejandro/sentinelguard/commit/5391ece7021e5128b151dfa67b5cb5daf9737883))
