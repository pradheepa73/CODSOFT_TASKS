"""Inject demo events so the dashboard has something to show."""
import random
import time

from aegis.core.events import bus, Event

MODULES = ["packet_eye", "phish_guard", "code_sentinel", "net_radar", "drop_vault"]
SEV = ["info", "low", "medium", "high", "critical"]
TITLES = {
    "packet_eye": "Flow 10.0.0.4:51001 -> 8.8.8.8:53 risk={r:.2f}",
    "phish_guard": "Email verdict: phishing ({r:.2f})",
    "code_sentinel": "scan.py: 3 findings (score={r:.2f})",
    "net_radar": "MITRE stage: CommandAndControl ({r:.2f})",
    "drop_vault": "Anomalous access by analyst-3",
}


def main() -> None:
    for i in range(120):
        m = random.choice(MODULES)
        sev = random.choices(SEV, weights=[30, 30, 20, 15, 5])[0]
        r = random.random()
        bus.emit(Event(
            module=m, severity=sev,
            title=TITLES[m].format(r=r),
            detail={"demo": True, "n": i},
        ))
        time.sleep(0.01)
    print("Seeded 120 demo events.")


if __name__ == "__main__":
    main()