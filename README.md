# LB 183 | <br> 🔒 Einblicke in die Welt der Applikationssicherheit 🔒

## **Inhaltsverzeichnis**

- [Einleitung](#einleitung)
- [Handlungsziel 1](#hz1)
  - [Artefakt | Top 3 Sicherheitsrisiken](#artefaktHz1)
    - [Broken Access Control](#brokenAccessControl)
    - [Cryptographic Failures](#cryptographicFailures)
    - [Injection](#injection)
  - [Wie wurde das HZ erreicht](#erreiHz1)
  - [Erklärung Artefakt](#erkläHz1)
  - [Beurteilung Erreichungsgrad](#beurtHz1)
- [Handlungsziel 2](#hz2)
  - [Artefakt | Code vor und nach Implementierung der Massnahme ](#artefaktHz2)
  - [Wie wurde das HZ erreicht](#erreiHz2)
  - [Erklärung Artefakt](#erkläHz2)
  - [Beurteilung Erreichungsgrad](#beurtHz2)
- [Handlungsziel 3](#hz3)
- [Handlungsziel 4](#hz4)
- [Handlungsziel 5](#hz5)

<a id="einleitung"></a>

## Einleitung

Dieses Repository dient der Dokumentation der Leistungsbeurteilung des Moduls 183. Diese gliedert sich in fünf Handlungsziele, für die jeweils ein Artefakt erstellt wird, um die Zielerreichung nachweisen zu können. Nachfolgend sind die einzelnen Handlungsziele mit ihrer Gewichtung aufgeführt.

| HZ  | Handlungsziel                                                                                                                                                                           | Gewichtung |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| 1   | Aktuelle Bedrohungen erkennen und erläutern können. Aktuelle Informationen zum Thema (Erkennung und Gegenmaßnahmen) beschaffen und mögliche Auswirkungen aufzeigen und erklären können. | 10%        |
| 2   | Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können. Gegenmaßnahmen vorschlagen und implementieren können.                                                         | 30%        |
| 3   | Mechanismen für die Authentifizierung und Autorisierung umsetzen können.                                                                                                                | 20%        |
| 4   | Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen.                                                                                           | 30%        |
| 5   | Informationen für Auditing und Logging generieren. Auswertungen und Alarme definieren und implementieren.                                                                               | 10%        |

<a id="hz1"></a>

# **Handlungsziel 1**

<a id="artefaktHz1"></a>

## Artefakt | Top 3 Sicherheitsrisiken

Als Grundlage für meine Übersicht habe ich den [OWASP Top Ten 2021 Bericht ](https://owasp.org/www-project-top-ten/) verwendet, dieser ist Stand 18.12.2023 die neuste Publikation auf der OWASP Top Ten Webseite.

---

<a id="brokenAccessControl"></a>

### **Broken Access Control (BAC)**

#### **_Was ist es?_**

Wie der Name es schon sagt, handelt es sich bei „Broken Access Control“, um eine kaputte Zugangskontrolle. Das bedeutet, dass UserInnen aufgrund von einer schlechten oder gar nicht vorhandenen Kontrolle sich Zugriff auf Daten oder Funktionen erschleichen, auf die sie keinen Zugriff haben sollten. Die Angriffe können dabei vielfältig sein, ungeschützte API-Endpoints, URLs ohne Kontrolle und noch vieles mehr.

#### **_Was sind die Folgen?_**

Die Folgen von BAC können in ihrem Schaden stark variieren. Von Daten, die eigentlich nicht eingesehen werden sollten, zu ganzen Datenbank, die durch unberechtigten Zugriff gelöscht werden, ist alles dabei.

#### **_Wie erkennt man es?_**

Um eine Software auf BAC zu überprüfen, gibt es hauptsächlich drei Wege:

- **Manuelles Testen** <br>
  Alle Angriffspunkte werden bestimmt (API-Calls, URLs etc.) und anschliessend von Hand getestet, um zu überprüfen, dass keine unautorisierten Zugriffe möglich sind.
- **Automatisches Testen** <br>
  Skript und Tools, welche das Programm automatisch überprüfen, werden eingesetzt. Verbreitete Optionen sind ZAP und Burp Suite.
- **Penetrationstesten** <br>
  Ein White-Hat versucht die Applikation zu hacken und so BAC-Sicherheitslücken zu finden. Diese Testart kann sehr aufwändig und teuer sein, je nach dem aber wichtige Resultate bringen.

#### **_Wie kann man es verhindern?_**

- **Deny by default** <br>
  Wenn es sich nicht um öffentliche Ressourcen handelt, sollte man den Zugriff verweigern und erst nach Verifizierung erlauben.
- **Wiederverwenden von Mechanismen** <br>
  Access Control Mechanismen einmal richtig implementieren und dann in der Applikation wiederverwenden.
- **Zugriff begrenzen** <br>
  Nur eine gewisse Anzahl an API- und Controller-Zugriffen zulassen, um so automatisierte Angriffe gestoppt werden können.

---

<a id="cryptographicFailures"></a>

### **Cryptographic Failures (CF)**

#### **_Was ist es?_**

Cryptographic Failures umfasst alle Aspekte der Verschlüsselung und Kryptografie, die ein Risiko darstellen. Dazu gehören die Nichtverschlüsselung von Daten, z. B. beim Senden von HTTP-Anfragen oder beim Speichern in der Datenbank, die Verwendung schlechter/alter Verschlüsselungsalgorithmen, schwache Schlüssel oder sogar Standardschlüssel, die in der Anwendung verwendet werden und mehr.

#### **_Was sind die Folgen?_**

Cryptographic Failures können dazu führen, dass vertrauliche Daten veröffentlicht werden und dadurch das Vertrauen in die Anwendung sinkt, was BenutzerInnen dazu veranlasst, auf eine Alternative auszuweichen. Darüber hinaus können Anmeldeinformationen, wenn diese involviert sind, missbraucht werden und, wie im Fall von BAC, dazu verwendet werden, Datenbanken oder andere Systeme anzugreifen und zu beschädigen.

#### **_Wie erkennt man es?_**

- **Daten-Checks** <br>
  Datenbanken überprüfen, sind alle Werte entsprechend geschützt, ggf. DSGVO und andere Gesetzte beiziehen und auf Verstösse prüfen.
- **Verkehr Überwachen** <br>
  Tools wie Wireshark verwenden, um den Datenverkehr der Applikation zu überwachen und möglich gefährdete Daten zu lokalisieren.
- **Versionen prüfen** <br>
  Hash- und Verschlüsselungsalgorithmen auf Aktualität und Sicherheit prüfen.

#### **_Wie kann man es verhindern?_**

- **Konzept für Daten** <br>
  Bei der Planung einer Applikation verschiedene behandelte Daten in Gruppen einteilen, sensible Daten immer verschlüsselt speichern.
- **Unnötige Gefahr vermeiden** <br>
  Sensible Daten nur dann speichern, wenn man auch wirklich muss.
- **Aktualität** <br>
  Immer aktuelle und sichere Algorithmen & Protokolle verwenden.
- **Die Gefahr der Übertragung** <br>
  Daten auch beim Übertragen immer verschlüsseln, da der Verkehr abgehört werden kann.

---

<a id="injection"></a>

### **Injection**

#### **_Was ist es?_**

Um Injection handelt es sich, wenn zusätzlicher Code über Inputs in eine Applikation eingespeist wird, um so ungewollte Aktionen hervorzurufen. Beispielsweise würden bei einer Injection vermeidliche Daten eingegeben werden, da diese jedoch eine spezielle Struktur haben, werden sie vom Programm als Anweisung angesehen und somit ausgeführt.

#### **_Was sind die Folgen?_**

Abgesehen von direktem Schaden an der Datenbank, durch löschen, verändern oder hinzufügen von Daten, können auch hier sensible Daten gestohlen werden, was zu Identitätsdiebstahl (mit Benutzerdaten) und Rufschaden führen kann.

#### **_Wie erkennt man es?_**

- **Struktur prüfen** <br>
  Struktur von Benutzereingaben im eigenen Code prüfen, wird an jeder Stelle verhindert, dass Injections stattfinden können.
- **Automatisierte Suche** <br>
  Wie auch bei BAC, gibt es für Injection Tools, welche die eigene App auf Schwachstellen prüfen. Verbreitete Optionen sind erneut ZAP und Burp Suite.
- **Penetrationstesten** <br>
  Hier gilt das gleiche wie bei BAC Penetrationstests.
  Ein White-Hat versucht die Applikation zu hacken und so
  Injection-Sicherheitslücken zu finden. Diese Testart kann sehr aufwändig und teuer sein, je nach dem aber wichtige Resultate bringen.

#### **_Wie kann man es verhindern?_**

- **Parameterized Statements** <br>
  Anstatt die Daten in das Statement einzufügen, dieses anschliessend zu kompilieren und auszuführen, wird hier das Statement bereits kompiliert und die Daten erst danach eingefügt. So kann verhindert werden, dass die Daten als Anweisung angesehen werden.
- **Whitelisting** <br>
  Diese Variante macht nur Sinn, wenn man einen Input hat, welcher eine begrenzte Anzahl an Möglichen und bekannten Inputs hat, da man eine Liste von akzeptierten Inputs erstellt und alles andere ablehnt.
- **Escaping** <br>
  Eine weitere bekannte Möglichkeit, um sich vor Injections zu schützen ist Escaping, dabei werden spezielle Zeichen (z.B. Anführungszeichen) in einem gewissen Kontext durch explizite Deklaration unschädlich gemacht. Wichtig zu beachten ist, dass Escaping in einigen Fällen nichts bewirkt. Zum Beispiel sind Zahlen in einer SQL-Abfrage oft nicht in Anführungszeichen, wodurch Escaping von Anführungszeichen hier nicht bringt. Bei dieser Methode ist es daher wichtig, das Escaping auf Sprache und Kontext anzupassen.

<a id="erreiHz1"></a>

## Wie wurde das HZ erreicht

Durch die Erstellung des "Top 3 Sicherheitsrisiken" Berichts habe ich zunächst aktuelle Bedrohungen bekannt, da ich mich beim neusten Top Ten OWASP Bericht über Gefahren informiert habe und weiter habe ich in der folgenden Recherche aktuelle Informationen zu den einzelnen Themen gefunden und so Erkennung der Gefahr, mögliche Gegenmassnahmen sowie Auswirkung der Gefahr jeweils erläutert.

<a id="erkläHz1"></a>

## Erklärung Artefakt

Mein Artefakt, zu diesem Handlungsziel, ist ein Bericht zu den Top 3 Sicherheitsrisiken 2023. Er hat das Ziel, LeserInnen zu erklären, was die drei grössten Sicherheitsgefahren sind, was deren Auswirkungen sind und wie man diese erkennen sowie bekämpfen kann.

<a id="beurtHz1"></a>

## Beurteilung Erreichungsgrad

Hinsichtlich des Moduls würde ich dieses Handlungsziel als vollständig erreicht ansehen, da ich alle gewünschten Punkte berücksichtig habe, vom Modul abgesehn ist jedoch zu beachten, dass die gezeigten Risiken nur die drei häufigsten sind und es leider noch ganz viele andere Risiken gibt.

<a id="hz2"></a>

# Handlungsziel 2

<a id="artefaktHz2"></a>

## Artefakt | Code vor und nach Implementierung der Massnahme

Im folgendem Block sehen Sie den Code **vor** der Implementierung der Sicherheitsmassnahme:

```csharp
[HttpPost]
[ProducesResponseType(200)]
[ProducesResponseType(400)]
[ProducesResponseType(401)]
public ActionResult<User> Login(LoginDto request)
{
    if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
    {
        return BadRequest();
    }

    string sql = $"SELECT * FROM Users WHERE username = '{request.Username}' AND password = '{MD5Helper.ComputeMD5Hash(request.Password)}'";
    User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();

    if (user == null)
    {
        return Unauthorized("login failed");
    }
    return Ok(user);
}
```

Im folgendem Block sehen Sie den Code **nach** der Implementierung der Sicherheitsmassnahme:

```csharp
[HttpPost]
[ProducesResponseType(200)]
[ProducesResponseType(400)]
[ProducesResponseType(401)]
public ActionResult<User> Login(LoginDto request)
{
    if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
    {
        return BadRequest();
    }

    string sql = "SELECT * FROM Users WHERE username = {0} AND password = {1}";
    User? user = _context.Users.FromSqlRaw(sql, request.Username, MD5Helper.ComputeMD5Hash(request.Password)).FirstOrDefault();

    if (user == null)
    {
        return Unauthorized("login failed");
    }
    return Ok(user);
}
```

<a id="erreiHz2"></a>

## Wie wurde das HZ erreicht

Um auf die Idee zu kommen, den Code zu überarbeiten und ihn so gegen Injections zu schützen, musste ich ihn zuerst analysieren und die Gefahr sehen, dass gezielten falschen Eingabe das Login überlisten könnten. So habe ich eine Sicherheitslücke (SQL-Injection) und deren Ursache (Eingaben direkt im SQL-Query) erkannt und anschliessend mit dem Vorschlag Parameterized Statements, vorgestellt im HZ1, welchen ich anschliessend implementierte, geschlossen.

<a id="erkläHz2"></a>

## Erklärung Artefakt

Mein Artefakt für das Handlungziel 2 besteht aus dem Code vor und nach der Überarbeitung. <br> <br>
Im Code vor der Überarbeitung ist es möglich sich in einen Account (egal ob User oder Admin Account) einzuloggen, nur mit dem Wissen, wie der Benutzername lautet, ohne aber das Passwort zu kennen. Gibt es so beispielsweise einen Benuter mit dem Name `administrator` so kann man einfach als Benutzername `administrator' --` und als Passwort jeden Wert ausser `NULL` angeben und schon ist man eingeloggt. <br> <br>
Schaut man sich folgenden Code an wird klar warum: <br>

```csharp

string sql = $"SELECT * FROM Users WHERE username = '{request.Username}' AND password = '{MD5Helper.ComputeMD5Hash(request.Password)}'";
User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();

```

Auf der ersten Zeile wird die SQL-Abfrage definiert, dabei wird der erhaltene Username einfach eingefügt. Die Eingabe `administrator' --` verursacht daher, dass zunächst durch das `'` der String als beendet betrachtet wird und die `--` , welche in SQL anzeigen, dass ein Kommentar kommt, bewriken das dieser ganze Code `AND password = '{MD5Helper.ComputeMD5Hash(request.Password)}'"` nicht mehr ausgeführt wird. <br>
In der folgenden Anfrage, an die Datenbank, wird daher einfach nach dem Username gesucht und wenn dieser gefunden wurde der Loginprozess als erfüllt betrachtet und dem bösen Hacker oder der bösen Hackerin wird der Zugang ermöglicht. <br> <br>

Im Code nach der Überabrbeitung habe ich Parameterized Statements implementiert: <br>

```csharp

string sql = "SELECT * FROM Users WHERE username = {0} AND password = {1}";
User? user = _context.Users.FromSqlRaw(sql, request.Username, MD5Helper.ComputeMD5Hash(request.Password)).FirstOrDefault();

```
Auf der ersten Zeile, in der SQL-Abfrage, werden daher `username` und `password` mit `{0}` bzw. `{1}` definiert, ohne die richtig Benutzerdaten einzufügen.
In der folgenden Datenbank anfrage werden dabei der eingegeben Username und das eingeben Passwort als Parameter sepparat mitgegben, wodurch die Datenbank weiss, dass diese nur Daten und kein Code sind. 


<a id="beurtHz2"></a>

## Beurteilung Erreichungsgrad

Das Handlungsziel 2 würde ich als vollständig erreicht betrachten, ich habe eine Sicherheitslücke gefunden, den Lösungsvorschlag vom HZ1 auf so ein Problem genommen und diesen erfolgreich implementiert. Es ist hinzuzufügen, dass ich jedoch nicht alle Sicherheitsrisiken im Code geschlossen habe. So wird beispielsweise als Hash-Algorithmus, für die Passwörter, MD5 verwendent, welcher als nicht mehr sicher gilt und daher ein Sicherheitsrisiko (Cryptographic Failure) darstellt. Einen möglichen Lösungsansatz diesen zu schliessen wäre, in der Applikation einen sicheren Algorithmus wie Argon2 oder Bcrypt zu verwenden. 

<a id="hz3"></a>

# Handlungsziel 3

<a id="artefaktHz3"></a>

## Artefakt | Code vor und nach Implementierung der Massnahme

<a id="erreiHz3"></a>

## Wie wurde das HZ erreicht

asdfasdf

<a id="erkläHz3"></a>

## Erklärung Artefakt

asfdsdf

<a id="beurtHz3"></a>

## Beurteilung Erreichungsgrad

asdfasdf

<a id="hz4"></a>

# Handlungsziel 4

<a id="artefaktHz4"></a>

## Artefakt | Code vor und nach Implementierung der Massnahme

<a id="erreiHz4"></a>

## Wie wurde das HZ erreicht

asdfasdf

<a id="erkläHz4"></a>

## Erklärung Artefakt

asfdsdf

<a id="beurtHz4"></a>

## Beurteilung Erreichungsgrad

asdfasdf

<a id="hz5"></a>

## Handlungsziel 5

<a id="artefaktHz5"></a>

## Artefakt | Code vor und nach Implementierung der Massnahme

<a id="erreiHz5"></a>

## Wie wurde das HZ erreicht

asdfasdf

<a id="erkläHz5"></a>

## Erklärung Artefakt

asfdsdf

<a id="beurtHz5"></a>

## Beurteilung Erreichungsgrad

asdfasdf

