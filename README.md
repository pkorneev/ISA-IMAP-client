# README

## Autor

**Jméno:** Pavlo Kornieiev  
**Login:** xkorni03

## Datum vytvoření

**Datum:** 16.11.2024

## Popis programu

Program **imapcl** je navržen pro čtení elektronické pošty pomocí protokolu IMAP4rev1 (RFC 3501).

Po spuštění tento program:

- Stáhne všechny zprávy uložené na zadaném IMAP serveru.
- Uloží je jako samostatné soubory do zadaného adresáře.
- Na standardní výstup vypíše počet úspěšně stažených zpráv.

Program umožňuje upravit svou funkcionalitu prostřednictvím dodatečných parametrů příkazové řádky, které umožňují:

- Nastavení šifrování (TLS/SSL).
- Specifikaci schránky (např. INBOX).
- Práci pouze s novými zprávami.
- Stahování pouze hlaviček zpráv.

Tento nástroj je užitečný pro správu e-mailů na serveru pomocí příkazové řádky s přizpůsobitelnými možnostmi chování.

## Použití

Program lze zkompilovat pomocí nástroje `make`. Kompilace probíhá na základě souboru `Makefile`, který obsahuje instrukce pro sestavení hlavního zdrojového souboru `imapcl.c`.

```bash
./imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth file [-b MAILBOX] -o out dir
```

### Popis parametru

| Parametr       | Povinný/Volitelný | Popis                                                                                               |
| -------------- | ----------------- | --------------------------------------------------------------------------------------------------- |
| **server**     | Povinný           | Název serveru (doménové jméno nebo IP adresa).                                                      |
| `-p port`      | Volitelný         | Číslo portu na serveru. Výchozí hodnota závisí na použití šifrování (TLS/SSL).                      |
| `-T`           | Volitelný         | Zapne šifrování TLS/SSL (imaps). Pokud není tento parametr uveden, použije se nešifrovaný IMAP.     |
| `-c certfile`  | Volitelný         | Soubor s certifikáty pro ověření SSL/TLS certifikátu serveru.                                       |
| `-C certaddr`  | Volitelný         | Adresář s certifikáty pro ověření SSL/TLS certifikátu serveru. Výchozí hodnota je `/etc/ssl/certs`. |
| `-n`           | Volitelný         | Zpracuje pouze nové zprávy (ignoruje již stažené).                                                  |
| `-h`           | Volitelný         | Stáhne pouze hlavičky zpráv, nikoliv jejich celé tělo.                                              |
| `-a auth_file` | Povinný           | Cesta k souboru s přihlašovacími údaji.                                                             |
| `-b MAILBOX`   | Volitelný         | Název schránky (např. `INBOX`). Výchozí hodnota je `INBOX`.                                         |
| `-o out_dir`   | Povinný           | Cesta k výstupnímu adresáři, do kterého se uloží stažené e-maily.                                   |

### Příklad kompilace

```bash
make
```

### Příklad spuštění

```bash
./imapcl imap.pobox.sk -p 993 -T -a auth_file -o maildir
```

Tento příkaz se připojí k serveru imap.pobox.sk na portu 993 s povoleným šifrováním TLS. K autentizaci použije přihlašovací údaje ze souboru auth_file a stažené e-maily uloží do adresáře maildir.
