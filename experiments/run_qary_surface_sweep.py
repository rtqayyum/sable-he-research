import csv
import sys
from sable.estimator_c2 import c2_dictionary_entries
from sable.params import PRESETS
from sable.qary_lpn_estimator import estimate_qary_lpn_surface


def main() -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow(['preset', 'surface', 'q', 'n', 'samples', 'eta', 'ratio', 'min_bits', 'passes', 'qary_bkw_bits', 'qary_bkw_block', 'qary_bkw_finite'])
    for name in ['c2_toy_noisy', 'c2_design_smallq', 'c2_candidate_depth1']:
        p = PRESETS[name]
        surfaces = [
            ('expansion', p.n, p.q, p.eta, p.N * p.N, p.k),
            ('seeded_dictionary_compaction', p.n_c, p.q, p.eta_c, c2_dictionary_entries(p.q, p.N, p.c2_block_size) * p.m_c, None),
        ]
        for surface, n, q, eta, samples, row_weight in surfaces:
            report = estimate_qary_lpn_surface(name=surface, n=n, q=q, eta=eta, samples=samples, row_weight=row_weight)
            bkw = report['qary_bkw_block_scan']
            writer.writerow([name, surface, q, n, samples, eta, f"{report['sample_to_dimension_ratio']:.6g}", report['conservative_min_bits'], report['passes_target_screen'], bkw['bits'], bkw['block_size'], bkw['finite_samples_available']])


if __name__ == '__main__':
    main()
