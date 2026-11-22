# Changelog

## v0.3.0 (2026-11-22): first public release, format frozen

* Format v0.3 frozen (see SPEC.md, section 10 for changes from v0.2):
  signing tag "DigiHan/v1"; bit 0 at 12 o'clock under the key bridge; guard band 1.2 mm;
  one size (45 mm, 0.6 mm modules).
* Decoders (Python and phone): keep only plausible bridge readings; re-refine the start angle
  when retrying without the bridge calibration. Phone decoder: 196/220 -> 216/220 on the stress rig.
* Verifier rejects unknown versions and reserved flags.
* Released under Apache-2.0; SPEC.md in the public domain (CC0 1.0).
