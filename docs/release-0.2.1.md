# Celatim 0.2.1

Celatim 0.2.1 corrects the TLS 1.3 record-padding mechanism used by the survey
artifact. RFC 8446 requires every padding octet in `TLSInnerPlaintext.zeros` to be
zero, so the controllable symbol is the padding-run length rather than arbitrary
padding content.

The corrected catalog row:

- reports 14 structural bits per record, representing padding lengths 0 through
  16,383;
- has no fictitious fixed field locator;
- is classified as a codec/serialized-structure check rather than real on-wire TLS
  evidence; and
- rejects nonzero padding octets in its parser fixture.

The transfer protocol and its providers are unchanged. The release gate runs the
complete test suite, an installed-wheel smoke outside the checkout, the explicit TLS
padding regression, all optional extras, a direct authenticated transfer, and the
locked dependency audit.
