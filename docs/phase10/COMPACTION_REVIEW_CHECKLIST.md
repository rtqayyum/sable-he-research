# Compaction review checklist

- Does the submitted scheme use coordinate compaction as the conservative main
  proposal?
- If an optimized mask family is used, what is its sparse mask-kernel distance?
- Are public CLPN rows, row differences, and mask-kernel relations all counted?
- Is q-ary compaction-noise piling-up below the chosen decoder threshold?
- Are block dictionaries clearly marked as optional and externally unreviewed?
- Does the proof separate correctness from relation-resistance?
- Does the benchmark section report the cost of conservative coordinate
  compaction rather than only optimized dictionaries?
