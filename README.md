# OctoKlipScan
Einfacher Python-Scanner fuer OctoPrint, Klipper und Elegoo Centurio im lokalen LAN.
Ideal, um schnell die IPs der Drucker im Netzwerk zu finden.

## Funktionen
- Scannt typische Ports fuer OctoPrint, Klipper (Moonraker) und Elegoo Centurio.
- Erkennt Hosts per HTTP-Banner und typischen Endpunkten.
- Automatische Erkennung lokaler /24-Netze (aus lokalen IPs).
- Optionaler Scan einzelner Hosts oder eigener CIDR-Netze.
- Fortschrittsanzeige im Terminal.
- Debug-Logdatei im aktuellen Ordner fuer Fehlersuche.
- Keine externen Abhaengigkeiten (nur Python-Standardbibliothek).

## Voraussetzungen
- Python 3.10 oder neuer.

## Schnellstart
Aus dem Repo-Root:

```powershell
python src/lan_scan.py
```

Wenn du bereits IPs kennst:

```powershell
python src/lan_scan.py --hosts 192.168.1.167,192.168.1.174
```

## Einsteiger-Guide
1. Oeffne ein Terminal im Repo-Ordner.
2. Starte den Scan mit `python src/lan_scan.py`.
3. Warte, bis der Fortschrittsbalken fertig ist.
4. Lies die Ausgabe: gefundene Hosts werden pro Dienst aufgelistet.

Beispielausgabe:

```text
OctoPrint:
  192.168.1.167 (Ports: 80)
  192.168.1.174 (Ports: 80, 443)
Klipper:
  192.168.1.243 (Ports: 7125)
```

## Optionen
- `--hosts IP,IP` scannt nur die angegebenen Hosts.
- `--cidr NETZ` scannt ein bestimmtes Netz, z. B. `192.168.178.0/24`.
  Mehrere Netze koennen komma-getrennt angegeben werden.
- `--timeout SEKUNDEN` setzt das Timeout pro Port (Standard: 0.6).
- `--workers ANZAHL` setzt die Anzahl der parallelen Threads (Standard: 64).
- `--log DATEI` schreibt Debug-Logs in eine Datei (Standard: `lan_scan.log`).

## Tipps
- Wenn nichts gefunden wird, pruefe, ob deine Drucker im selben Netz sind.
- Erhoehe das Timeout bei langsamen WLANs, z. B. `--timeout 1.5`.
- Nutze `--hosts`, wenn du die IPs schon kennst.
