# Changelog

## [0.5.0](https://github.com/iExec-Nox/nox-kms/compare/v0.4.0...v0.5.0) (2026-03-27)


### Features

* add docker release gha ([#32](https://github.com/iExec-Nox/nox-kms/issues/32)) ([4edc282](https://github.com/iExec-Nox/nox-kms/commit/4edc2822af8f53db1450c64f75e3e5c996d6a34b))
* add prometheus metrics ([#8](https://github.com/iExec-Nox/nox-kms/issues/8)) ([52ff4da](https://github.com/iExec-Nox/nox-kms/commit/52ff4da60f638874bc42184093aa511af7bd3b37))
* add wallet and persist ([#11](https://github.com/iExec-Nox/nox-kms/issues/11)) ([a0f87ea](https://github.com/iExec-Nox/nox-kms/commit/a0f87ea32a505d9733d189263f8c6464f7506aab))
* check gateway authorization ([#13](https://github.com/iExec-Nox/nox-kms/issues/13)) ([fd08ee2](https://github.com/iExec-Nox/nox-kms/commit/fd08ee2ed03fae97f2d0c43569c3691543c15438))
* expose delegate endpoint ([#6](https://github.com/iExec-Nox/nox-kms/issues/6)) ([3c81530](https://github.com/iExec-Nox/nox-kms/commit/3c81530a53e4f253e7630916dc7079fda9a84e9d))
* expose public key in hexa ([#5](https://github.com/iExec-Nox/nox-kms/issues/5)) ([5b3f33c](https://github.com/iExec-Nox/nox-kms/commit/5b3f33c61fd9453396a2579ca30e4789826583c9))
* fetch gateway address on-chain for signature validation ([#18](https://github.com/iExec-Nox/nox-kms/issues/18)) ([bf6ddcb](https://github.com/iExec-Nox/nox-kms/commit/bf6ddcb58d5a96e2088c81c7dd8f271ebc84da98))
* fully init project ([#1](https://github.com/iExec-Nox/nox-kms/issues/1)) ([836654c](https://github.com/iExec-Nox/nox-kms/commit/836654c354a24e4e25050db9a4d36172d87f406b))
* generate and persist key pair ([#4](https://github.com/iExec-Nox/nox-kms/issues/4)) ([d6ee613](https://github.com/iExec-Nox/nox-kms/commit/d6ee613b4455f48d6929c7f72e6fd974153225f8))
* inject keys into env variables ([#21](https://github.com/iExec-Nox/nox-kms/issues/21)) ([4a8637b](https://github.com/iExec-Nox/nox-kms/commit/4a8637bbae3aca0de3be4649d84a14c6cdbbd2de))
* limit HTTP metrics to the defined endpoints ([#26](https://github.com/iExec-Nox/nox-kms/issues/26)) ([282620d](https://github.com/iExec-Nox/nox-kms/commit/282620de6cee64b943d9cde1b6377277caa75c42))
* sign delegate response ([#14](https://github.com/iExec-Nox/nox-kms/issues/14)) ([55942ee](https://github.com/iExec-Nox/nox-kms/commit/55942ee893e1ce0220bb0d03db08632c4a9ddb78))
* sign pubkey response and check files permissions ([#12](https://github.com/iExec-Nox/nox-kms/issues/12)) ([3e76f28](https://github.com/iExec-Nox/nox-kms/commit/3e76f28fa9bc488ebaa4a1773b5cef323ba1be43))


### Bug Fixes

* add 0x prefix to pubkey ([#7](https://github.com/iExec-Nox/nox-kms/issues/7)) ([03f9102](https://github.com/iExec-Nox/nox-kms/commit/03f9102d95848fe706d1ba8b3eae4d7d290fc98e))
* do not start KMS if Handle Gateway address  is not configured on-chain ([#25](https://github.com/iExec-Nox/nox-kms/issues/25)) ([82dfbb4](https://github.com/iExec-Nox/nox-kms/commit/82dfbb42be2f7177bbbb8c7417e9aae563422e32))
* re-order dependencies ([#9](https://github.com/iExec-Nox/nox-kms/issues/9)) ([318ca9d](https://github.com/iExec-Nox/nox-kms/commit/318ca9d72458e081147ff446692333928d8bc80b))
* update VERSIONED_PATHS format to use path parameters correctly ([#28](https://github.com/iExec-Nox/nox-kms/issues/28)) ([19e617e](https://github.com/iExec-Nox/nox-kms/commit/19e617e6bf85e38b9e72b2864d01903f2348d998))
* use 0x-prefixed keys for delegate authorization ([#24](https://github.com/iExec-Nox/nox-kms/issues/24)) ([44c9ad2](https://github.com/iExec-Nox/nox-kms/commit/44c9ad2c45731a8c988c7d47911ff4689211b258))
* Use alpine 3.23 image to have CA certificates at runtime ([#20](https://github.com/iExec-Nox/nox-kms/issues/20)) ([9b8835d](https://github.com/iExec-Nox/nox-kms/commit/9b8835d49450b182dd393179d4bf0e427f380fa6))
* use structured responses in endpoints ([#10](https://github.com/iExec-Nox/nox-kms/issues/10)) ([ebedde2](https://github.com/iExec-Nox/nox-kms/commit/ebedde27ea33113757346b17334bd83ec6fb4c44))
