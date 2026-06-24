# Security game

The Phase 6 security game is secret-key IND-CPA with public evaluation keys. The adversary receives parameters, the expansion key, the compaction key, and public algorithms. It can query an encryption oracle and receive one challenge ciphertext.

The proof target excludes chosen-ciphertext attacks, malicious parameter generation, side-channel leakage, decryption-failure oracle leakage, and certification of concrete parameters.
