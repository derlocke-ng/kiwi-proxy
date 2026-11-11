"""Where a module that takes several exits may leave: the forced countries and
relays ("Only"), the blocked countries ("Never"), and the Eyes group blocked for
every exit of such a module (Kiwi Proxy's Tor preference). Tor is the one module
that says it can (`exit_selection = True`); Mysterium's selection is its lease.

Each distinct selection gets its own provider container: a Tor process holds one
ExitNodes and one ExcludeExitNodes, so exits that want different ones cannot
share it. The container is keyed by a lease derived from the selection.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import countries, prefs, providers

FIVE = ("AU", "CA", "NZ", "GB", "US")
NINE = (*FIVE, "DK", "FR", "NL", "NO")
FOURTEEN = (*NINE, "BE", "DE", "IT", "ES", "SE")
EYES: dict[str, tuple[str, ...]] = {"five": FIVE, "nine": NINE, "fourteen": FOURTEEN}
EYES_TITLES = {
    "": "No group",
    "five": "Five Eyes",
    "nine": "Nine Eyes",
    "fourteen": "Fourteen Eyes",
}

_SUPPORTS: dict[str, bool] = {}


def supports(module: str | None) -> bool:
    """The module takes lists of countries and relays (a class attribute, read
    through getattr so older modules simply do not)."""
    if not module or not providers.manages(module):
        return False
    if module not in _SUPPORTS:
        try:
            prov, _m = providers.load(module)
            _SUPPORTS[module] = bool(getattr(prov, "exit_selection", False))
        except providers.ProviderError:
            return False
    return _SUPPORTS[module]


def blocked_everywhere() -> tuple[str, ...]:
    """The Eyes group the preference blocks for every Tor exit."""
    return EYES.get(prefs.load().tor_never_group, ())


@dataclass(frozen=True)
class Selection:
    only_countries: tuple[str, ...] = ()
    only_nodes: tuple[str, ...] = ()
    never_countries: tuple[str, ...] = ()  # this exit's own and the Eyes group's
    own_never: tuple[str, ...] = field(default=(), compare=False)
    # the Eyes group for every position (entry, middle, exit), when the preference says so
    never_anywhere: tuple[str, ...] = ()
    # A Tor Browser exit (socks_auth passthrough): a Tor of its own with a control
    # port for the gateway's filter. The exit's id keys the container; the
    # password is not part of the key.
    control_for: str = ""
    control_password: str = field(default="", compare=False, repr=False)

    @property
    def empty(self) -> bool:
        return not (
            self.only_countries
            or self.only_nodes
            or self.never_countries
            or self.never_anywhere
            or self.control_for
        )

    def key(self) -> str:
        """A lease for the provider container this selection needs."""
        text = (
            "|".join(
                ",".join(part)
                for part in (self.only_countries, self.only_nodes, self.never_countries)
            )
            + ("|all:" + ",".join(self.never_anywhere) if self.never_anywhere else "")
            + ("|ctl:" + self.control_for if self.control_for else "")
        )
        return "x" + hashlib.sha256(text.encode()).hexdigest()[:10]

    def problems(self) -> list[str]:
        both = sorted(set(self.only_countries) & set(self.own_never))
        out = []
        if both:
            out.append(f"{', '.join(both)} cannot be both Only and Never")
        group = set(self.never_countries) - set(self.own_never)
        blocked = sorted(set(self.only_countries) & group)
        if blocked:
            out.append(
                f"{', '.join(blocked)} {'is' if len(blocked) == 1 else 'are'} blocked for every "
                "Tor exit (Preferences, Tor)"
            )
        return out


def clean(codes) -> tuple[str, ...]:
    """Upper-case two-letter codes, sorted, without doubles; anything else raises."""
    out = set()
    for raw in codes or ():
        for code in str(raw).replace(" ", ",").split(","):
            code = code.strip().upper()
            if not code:
                continue
            if not countries.is_code(code):
                raise ValueError(f"{code!r} is not a two-letter country code")
            out.add(code)
    return tuple(sorted(out))


def clean_nodes(fingerprints) -> tuple[str, ...]:
    out = set()
    for raw in fingerprints or ():
        for fp in str(raw).replace(" ", ",").split(","):
            fp = fp.strip().lstrip("$").upper()
            if not fp:
                continue
            if len(fp) != 40 or any(c not in "0123456789ABCDEF" for c in fp):
                raise ValueError(f"{fp!r} is not a relay fingerprint (40 hex digits)")
            out.add(fp)
    return tuple(sorted(out))


def of(endpoint) -> Selection | None:
    """The selection an exit's endpoint asks for, with the Eyes group added; None
    for a module that does not take one."""
    if not supports(endpoint.module):
        return None
    only = list(endpoint.only_countries)
    if not only and endpoint.country:  # an exit made with --country before lists
        only = [endpoint.country]
    own = clean(endpoint.never_countries)
    group = blocked_everywhere()
    return Selection(
        only_countries=clean(only),
        only_nodes=clean_nodes(endpoint.only_nodes),
        never_countries=tuple(sorted(set(own) | set(group))),
        own_never=own,
        never_anywhere=tuple(sorted(group)) if prefs.load().tor_never_all else (),
    )


CONTROL_PORT = 9052  # the control port a Tor Browser exit's Tor opens on the bridge


def wants_control(ex) -> bool:
    """A Tor exit Tor Browser uses (passthrough): New Identity, the circuit display
    and onion-site keys need Tor's control port, behind the gateway's filter."""
    return ex.socks_auth == "passthrough" and supports(ex.endpoint.module)


def for_exit(ex) -> Selection | None:
    """The selection for a whole exit: its endpoint's, plus its own Tor and a
    control password when Tor Browser uses it."""
    import dataclasses

    sel = of(ex.endpoint)
    if sel is None or not wants_control(ex):
        return sel
    from . import secrets

    password = secrets.lookup(ex.id, kind="torcontrol")
    if not password:
        import secrets as rnd

        password = rnd.token_urlsafe(24)
        secrets.store(ex.id, password, kind="torcontrol")
    return dataclasses.replace(sel, control_for=ex.id, control_password=password)


def lease_for(ex) -> str | None:
    """The lease naming an exit's provider container (see lease_of), with a Tor
    of its own for a Tor Browser exit."""
    if ex.endpoint.lease:
        return ex.endpoint.lease
    if not wants_control(ex):
        return lease_of(ex.endpoint)
    sel = for_exit(ex)
    return sel.key() if sel else None


def lease_of(endpoint) -> str | None:
    """The lease that names the endpoint's provider container: its own lease, or
    for a module with a selection the selection's key (None: the module's shared
    container, for an exit that selects nothing)."""
    if endpoint.lease:
        return endpoint.lease
    sel = of(endpoint)
    return sel.key() if sel and not sel.empty else None


def summary(endpoint) -> str:
    """ "only DE, SE · never HU", for a row; "" when nothing is chosen."""
    sel = of(endpoint)
    if sel is None:
        return ""
    bits = []
    only = [*sel.only_countries, *(f"{len(sel.only_nodes)} relays",) * bool(sel.only_nodes)]
    if only:
        bits.append("only " + ", ".join(only))
    if sel.own_never:
        bits.append("never " + ", ".join(sel.own_never))
    return " · ".join(bits)
