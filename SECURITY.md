# Security

Please report security problems privately to **dp@modulo.network**. Include what you found, how to
reproduce it, and the version or commit. Do not open a public issue for a problem that could let
someone forge or alter a seal.

Known limits, stated in the README: the reference BIP340 code is pure Python and not constant-time,
and the time in a seal is the signer's statement, not a proof of when it was made.
