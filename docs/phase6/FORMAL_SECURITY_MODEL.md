# Formal security model

SABLE-HE is modeled as a secret-key leveled HE scheme with a public evaluation key. The adversary may receive the public evaluation key, request polynomially many encryptions, choose challenge messages, and perform arbitrary public evaluation. The target notion is IND-CPA privacy for the challenge bit under sparse q-ary LPN and q-ary code/LPN assumptions.
