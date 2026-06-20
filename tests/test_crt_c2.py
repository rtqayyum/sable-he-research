from dataclasses import replace

from sable.crt import CRTModuli
from sable.params import PRESETS
from sable import sable_crt


def test_crt_roundtrip():
    crt = CRTModuli((5, 7, 11))
    x = 173
    assert crt.reconstruct(crt.residues(x)) == x % (5 * 7 * 11)


def test_crt_sable_c2_add_clean_small_lanes():
    base = PRESETS["toy_clean"]
    # Keep lanes tiny for a unit test.  q values are prime and pairwise coprime.
    p1 = replace(base, name="lane_17", q=17, n=8, k=1, n_c=8, m_c=17, replicas=3)
    p2 = replace(base, name="lane_19", q=19, n=8, k=1, n_c=8, m_c=17, replicas=3)
    kp = sable_crt.keygen([p1, p2], seed=99)
    a = sable_crt.encrypt(kp, 21, seed=100)
    b = sable_crt.encrypt(kp, 22, seed=101)
    c = sable_crt.eval_add(a, b)
    assert sable_crt.decrypt(kp, c) == 43
