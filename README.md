# sd-jwt

This crate is a tentative to implement [JWT Selective Disclosure](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html) in Rust 🦀

```text
           +------------+
           |            |
           |   Issuer   |
           |            |
           +------------+
                 |
            Issues SD-JWT
      including all Disclosures
                 |
                 v
           +------------+
           |            |
           |   Holder   |
           |            |
           +------------+
                 |
           Presents SD-JWT
    including selected Disclosures
                 |
                 v
           +-------------+
           |             |+
           |  Verifiers  ||+
           |             |||
           +-------------+||
            +-------------+|
             +-------------+
```
