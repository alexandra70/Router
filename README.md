# Router




Impementare:

    Pornesc de la rezolvarea laboratorului 4.
    Incep prin a popula tabela de rutare cu datele citite din fisier.
    Procesul de forwarding:
    Primesc pachete intr-un while(1) si trbuie sa le interpretez; pentru a face acest lucru
    extrag in primul rand headerul de ether pe care toate pachetele trebuie sa il aiba.
    Mai departe in functie de tipul de pachet transportat de acesta(arp sau ip) se executa 
    diferite lucuri; mai precis:
        Pentru un pachet de tip ip, in primul rand verific daca are checksumul in regula
        si daca are ttl-ul inca bun, in cazul in care ttl-ul nu corespunde trebuie sa transmit
        inapoi un mesaj de eroare in care sa ii comunic sursei ca pachetul acela a expirat, se trimit 
        spre sursa un pachet care contine un header de icmp de tip time exceeded.
        Mai departe verific daca pachetul imi este destinat mie(ruterului), vad daca pachetul meu
        contine un header de icmp de tipul request, in cazul in care nu am icmp dupa 
        headerul de ip, sau in cazul in care acesta nu este de tipul request, nu fac nimic.
        Ruterul trebuie sa raspunda doar la request cu un echo-replay.

        Cazul in care nu am un pachet destinat ruterului, deci trebuie sa vad cui il transmit mai
        departe, in acest caz trebuie sa caut in tabela de rutare ruta cea mai buna, aici gasesc
        next hopul(ip-ul next hopului, pentru a determina adresa mac a next hopului am nevoie si de arp)
        si interfata pe care trebuie sa transmit pachetul. 
        
        Daca gasesc si ruta(next hopul + interfata), mai am nevoie doar de adresa mac a next hopului de
 	care pot face rost din tabela arp, in cazul in care nu exista intrare in tabela arp pentru ip-ul 
	next hopului trebuie sa generez o cerere pe care sa o transmit tuturor dispozitivelor din retea, 
	deci transmit broadcast un pachet care este o cerere arp. 

        In cazul in care pachetul ce contine cererea arp ajunge la un dispozitiv care are ac adresa ip cu
        adresa ip a destinatiei din headerul de arp, atunci acesta va trimite inpoi un arp-replay, cu adresa
        lui mac completata in headele de arp si ether, astfel incat atunci cand la nivelul ruterului
        ajunge un arp-replay el va cauta in tabela lui arp sa vada daca exista intrare pentru acel ip,
        in caz ca nu exista acel ip in tabela; populez o noua intrare cu ip-ul si adresa mac extrase din 
        pachetul primit (arp-replay). In cazul in care aveam pachete netrimise, le epuizez acum daca se poate
        (am gasit mac pentru ip-destinatie al pachetului).
        De fiecare data cand primesc un arp replay incerc sa vad daca pot timite din pachetele salvate in vector
        - cele pe care nu am reusit sa le trimit pentru ca nu aveam mac-ul destinatiei, dacain continuare nu pot
        le las in vector pana cand primesc adresa mac a next-hop ului corespunzator acestui pachet.

        Daca nu gasesc o ruta pentru pachetul meu, trebuie sa trimit inapoi un mesaj de eroare spre sursa pachetului
        in care sa specific tipul erorii, si anume - destinaiton unreachable. Pentru acest lucuru imi creez 
        strucutri noi de ether, ip si icmp; in care copiez ce am nevoie, adaug totul la un pachet nou 
        si il trimit inapoi spre sursa pachetului; pe ac interfata pe care a venit.

        Daca toate au mers bine(am gasit si ruta si arp-ul) trebuie doar sa trimit pachetul pe interfata
        specifica next-hopului acestui pachet.   



        Pentru ARP: headeru de arp se afla imediat dupa ether, deci il extrag, verific sa vad ce fel de
        arp am: ma uit sa fie ori request ori replay.
            ARP-request: trebuie sa trimit inapoi spre sursa pachetului un arp-replay cu adresa mac a ruterului.
            ARP-replay: In urma unui ARP-request a fost transmis un astel de arp-replay in care pot usor sa
            gasesc in headerul arp adresa mac a sursei si ip-sursei, pe care la voi utiliza, in cazul in care
            nu le am deja in tabela arp le voi adauga.
            Daca primesc un arp-replay si in acelasi timp am si pachete netransmise, incerc sa le transmit.



Altele:
    Am folosit qsort pentru sortare tabelei de rutare, exact ca aici:
    https://www.geeksforgeeks.org/comparator-function-of-qsort-in-c/
    Am flosit strucutra laboratorului 4.
