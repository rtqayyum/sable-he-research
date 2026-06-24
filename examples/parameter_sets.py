"""List and screen SABLE-HE candidate parameter sets."""

from sable import parameter_sets

for screen in parameter_sets.screen_all():
    print(parameter_sets.format_screen(screen))
    print()
