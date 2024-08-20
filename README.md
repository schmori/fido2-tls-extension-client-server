# TLS-Erweiterung mit FIDO

## Architektur

![Architecture_FIDO_final_bg.png](..%2FBilder%2FArchitecture_FIDO_final_bg.png)

### Beschreibung

- Authentifikator kommuniziert wie gewohnt mit dem Client via CTAP
  - bei der java-webauthn-demo Webseite können neue Nutzer registriert werden
- Der Client fungiert wie gewohnt als Mittelsmann
- Neben dem TLS-Server existiert auch der WebAuthn-Server, welcher sich lokal auf der Festplatte die Credentials speichert
  - TLS- und WebAuthn-Funktionalitäten werden deshalb dementsprechend auf separaten Servern ausgeführt
    - in meinem Fall laufen beide als eine Einheit innerhalb eines Projekts
    - TLS Server kann via API Funktionen von WebAuthn-Server aufrufen 
  - RP besteht also aus TLS- und WebAuthn-Server
- Der RP Server selbst hat eine eigene Datenbank um sich die ephemeren Schlüsselpaare zu speichern
  - Der RP und WebAuthn Server können über HTTPS mit TLS1.3 kommunizieren, aber besser auf einer Maschine (sicherer)
- Idee für Implementierung:
  - java-webauthn-code Bibliothek auf WebAuthn-Sever nutzen und dessen Funktionalitäten an TLS weitergeben bzw. über HTTPS an TLS Server übergeben

## TLS Handshake inklusive FIDO

### Anmerkungen

- FIDO mit ID (FI)
  - resident PKCS (discoverable) → privater Schlüssel+Meta-Daten+UserHandle werden auf dem Authentifikator oder clientseitig gespeichert
  - RP generiert einen User Handle, welcher einen Identifikatoren beinhaltet (z.B. user.id) 
  - Dieser User Handle wird dann beim Authentifizieren an den RP geschickt um ihn damit zu authentifizieren
  
![Handshake_FI.jpg](..%2FBilder%2FHandshake_FI.jpg)
- FIDO mit Name (FN)
  - Credentials werden serverseitig gespeichert
  - aus diesem Grund ist ein Nutzername erforderlich, um die dazu passenden Credentials zu finden 
  - Meistens gehört dann auch ein Passwort dazu
  
![Handshake_FN.jpg](..%2FBilder%2FHandshake_FN.jpg)

### TLS Bibliotheken

- JSSE -> Wie sieht es mit Lizenzen aus?
  - Standard Java library für TLS bis Version 1.3
  - Klassen und APIs für TLS Protokolle (Sockets etc. für TLS Verbindungen)
  - gute Dokumentation, leicht zu implementieren
- BouncyCastle
  - Unterstützt TLS (auch PGP und viele weitere Protokolle) bis Version 1.3
  - Bietet viele Krypto-Algorithmen
  - Dokumentation ist vorhanden, aber chaotisch und schwer zu durchblicken
- Apache HttpClient
  - für HTTP Verbindungen, bietet auch Unterstützung für HTTPS
  - denke eher nicht geeignet, weil es für http ausgelegt ist
- Netty
  - basiert auf NIO
  - asynchrone, ereignisgesteuerte Netzwerk-Anwendung
  - Eher ungeeignet für TLS Extension, weil es auch eher für HTTP ausgelegt ist
  - TLS zu integrieren ist aufwendig 

### PROBLEME * LÖSUNG

- problem: welche bibliothek? -> siehe abschnitt davor
- meine erweiterung muss in die standard-java-bibliothek rein damit ich den tls-handshake erweitern kann
- problem: da ich in der standard-java-bib direkt arbeite, kann ich keine externen bibliotheken darin verwenden. muss also irgendwie nach außen kommunizieren via api calls
- ich muss an registrierungsdaten kommen --> das mache ich über rest api call an webauthn-yubico-server
- es gibt keine java-lib für die interaktion mit dem fido2-stick -> verwende python lib für die interaktion und binde das skript in java mit ein DONE
- die AuthenticatorAssertionResponse (wird von tls and den webauthn server geschickt) war nicht korrekt aufgebaut -> Lösung: tbd

### Anleitung um Extension zu bauen

- https://www.ietf.org/rfc/rfc6066.txt
- https://github.com/openjdk/jdk/blob/master/doc/building.md 
- https://openjdk.org/groups/build/doc/building.html
  1. in jdk/ navigieren
  2. bash configure --with-boot-jdk=/mnt/c/Programme/Java/jdk-21 
  3. make images -> fertige jdk liegt in jdk/build/*/jdk/bin/java -version
  4. bei änderungen in java.base: make java.base-java-only
  5. fertig 
- Einstellungen in Intellij:
  - File | Project Structure | Project | SDK -> dort eigene jdk wählen
  - File | Settings | Build, Execution & Deployment | Compiler | Java Compiler | Module | target bytecode version -> dort 23-ea eingeben 
  - in pom.xml -> dort 23-ea angeben 
  - Run Configuration | Build and Run -> dort eigene jdk angeben

### TODO:

- FIDOExtension.java weiter schreiben; finished CHFidoSpec; 
- nur resident keys!
- certificateVerify vom server -> da fido-daten rein machen 
- allow_credentials -> kann erstmal rausgelassen werden
- Architektur-Bild abändern --> TLS -und Webauthn-Server laufen auf gleichen maschine also keine HTTPS-Verb. notwendig
- publicKeyCredentialRequestOptions parsen und dann an tls erweiterung übergeben
- PROBLEM: um credentials zu erstellen und zu bekommen, muss javascript benutzt werden! also muss der client auf javascript basieren worauf ich dann in der jdk zugreifen kann!
- es gibt keine methode in java, die die credentials erstellt/darauf zugreifen kann. geht nur in javascript.
- ODER (muss nachgeforscht werden): kann ich von publicKeyCredentialRequestOptions erhalten!
- 29.04.2024: bekomme credentials über python skript vom fido stick -> server verwendet diese für authentifizierung
- nächster schritt: AuthenticatorAssertionResponse richtig bauen (siehe screenshot in downloads-ordner)
- 02.06: vorige arbeit anschauen und schauen, was genau er an java-webauthn-server schickt!

-----
- CTAP2: c bibliothek in Java aufrufen -> siehe link email
- java native interface
- POC auf Windows-Host
- CTAP ist ja an sich nicht Teil der Aufgabe, sondern TLS
-----

### Literatur

Related Work:
https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2021-02/SAR-PR-2021-02_.pdf
https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2020-04/SAR-PR-2020-04_.pdf

Masterarbeit:
https://de.overleaf.com/project/64a69eeba9212a0cb4a26f18

Yubico-Demo-Server:
https://developers.yubico.com/WebAuthn/WebAuthn_Walk-Through.html 

### Ideen für später

- Ideen:
  - /etc/hosts -> zertifikat + eigenem domain namen (faken)
  - Tests auf Sicherheit und Funktionalität
  - client und server nicht über https
  - tls und webauthn server können über https kommunizieren, müssen aber nicht (jetzt: auf gleicher Maschine) 
  - Anwendungsbeispiel auf tcp ebene, aber ohne http; mit client zertifikaten
    - zb jabber oder spotify -> client api
  - registrierung über webauthn-demo-server (daten in sqlite db speichern) ODER direkt über Terminal-Anwendung
  - tls server nimmt sich registrierungsdaten und führt damit authentifizierung durch
  - anstatt ctap mittels python zu nutzen, kann eine externe java-bib verwendet werden bei der bisher nur ctap für ein app-emulator implementiert ist -> diese kann umgeschrieben werden damit sie auch für terminal-java-anwendungen benutzt wird