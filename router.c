#include "queue.h"
#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(struct in_addr dest_ip) {
    size_t idx = -1;	

    for (size_t i = 0; i < rtable_size; i++) {
        if ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix) {
	    if (idx == -1) idx = i;
	    else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) idx = i;
	}
    }
    
    if (idx == -1)
        return NULL;

    else
        return &rtable[idx];
}

//inca nu merge cu varianta asta.
struct route_table_entry *get_best_route_b(struct in_addr dest_ip) {
	
    size_t i = 0;
    size_t sup = rtable_size;
    
    struct route_table_entry* entry = NULL; //si pastrez si intrarea
    while(i < sup) {
        size_t mid = i + (sup - i) / 2;
        if ((dest_ip.s_addr & rtable[mid].mask) == rtable[mid].prefix) {
                //dupa ce am gsait caut inapoi sa vad dc am sarit peste

                entry = &rtable[mid];
                size_t k = mid - 1;
                if(k <= 0) break; //nu mai am la stanga unde sa caut.
                if((dest_ip.s_addr & rtable[k].mask) == rtable[k].prefix) {
                        //inseamnace trebuie sa mai caut in itervalul [i, mid]
                        sup = mid;
                        continue;
                }
                //altfel nu mai am : ori unde sa ma duc, ori am trecut la alt prefix
                break;
	}
	if ((dest_ip.s_addr & rtable[mid].mask) < rtable[mid].prefix) {
	        //caut la inceputul tabelei
	        i = mid;
	        
	        continue;
	}
	if ((dest_ip.s_addr & rtable[mid].mask) > rtable[mid].prefix) {
	        //caut la inceputul tabelei
	        sup = mid;
	        continue;
	}
    }
    
    return entry;
}

//cautarea in tabela arp, din laborator.
struct arp_entry *get_arp_entry(struct in_addr dest_ip) {
        //printf("*********arp_entry******\n");
        //printf("*********   %d    ******\n", arp_table_len);
        
        for (size_t i = 0; i < arp_table_len; i++) {
        //struct in_addr a;
        //a.s_addr = arp_table[i].ip;
                 /*printf("*********   %x:%x:%x:%x:%x:%x   ----------  %s     ******\n", arp_table[i].mac[0], 
                 arp_table[i].mac[1],
                 arp_table[i].mac[2],
                 arp_table[i].mac[3],
                 arp_table[i].mac[4],
                 arp_table[i].mac[5],
                 inet_ntoa(a));*/
        }
        
        for (size_t i = 0; i < arp_table_len; i++) {
                //if (memcmp(&dest_ip, &arp_table[i].ip, sizeof(struct in_addr)) == 0)
                //if(dest_ip.s_addr == arp_table[i].ip) 

                if (memcmp(&dest_ip, &arp_table[i].ip, sizeof(struct in_addr)) == 0)
                    return &arp_table[i];       
        }

        return NULL;
}


void print(packet m) {
        struct ether_header *eth = (struct ether_header *) m.payload;
        printf("+ m.interface %d+\n", m.interface);
        printf("+++++++++++++ m.len %d+\n", m.len);
        printf("+++++++++++++ m.len %ld+\n", sizeof(packet));
        printf("[ ether_dhost %s\n", eth->ether_dhost);
        printf("cet e cu icmp %ld\n", (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)));
        printf(" ether_shost %c%c%c%c%c%c\n", eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
        printf(" ether_type %d]\n", eth->ether_type);
        
        
        struct in_addr a;
        if (ntohs(eth->ether_type) == 0x0806) {
                struct arp_header* arph;
                arph = (struct arp_header*)(m.payload + sizeof(struct ether_header));
 
                printf("[ arp mac dest %s\n", arph->tha);  
                printf("[ arp mac src %s\n", arph->sha);   
                a.s_addr =  arph->tpa; 
                printf("[ arp ip dest %s\n", inet_ntoa(a)); 
                a.s_addr =  arph->spa;   
                printf("[ arp ip src %s\n", inet_ntoa(a));  
                printf("[ arp op - ce e 1 = request si 2 = replay %d]\n", ntohs(arph->op));                
                return;                   
        }
        
        if (ntohs(eth->ether_type) == 0x0800) {
                struct iphdr *iph;
                struct icmphdr *icmph;
                iph = (struct iphdr *)(m.payload + sizeof(struct ether_header)); 
                icmph = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
                 
                printf("[ iphdr id %d\n", iph->id);
                printf("[ iphdr ttl %d\n", iph->ttl);
                printf("[ iphdr protocol %d\n", ntohs(iph->protocol));
                printf("[ iphdr check %d\n", iph->check);
                printf("[ iphdr len %d\n", ntohs(iph->tot_len));
                
                a.s_addr =  iph->saddr;
                printf("[ iphdr saddr %s\n", inet_ntoa(a));
                a.s_addr =  iph->daddr;
                printf("[ iphdr daddr %s\n", inet_ntoa(a));
                printf("[ iphdr id %d]\n", ntohs(iph->id));
                printf("[ icmphdr tyle %d]\n", ntohs(icmph->type));
   
        }
        return;
}

//functia comparator, pt qsort.
int comparator(const void *p, const void *q) {
    uint32_t prefix_r1 = ((struct route_table_entry *)p)->prefix;
    uint32_t prefix_r2 = ((struct route_table_entry *)q)->prefix; 
    //descendent p_r2, p_r1
    if(prefix_r1 == prefix_r2) {
        //ordonez dupa masca
        uint32_t mask_r1 = ((struct route_table_entry *)p)->mask;
        uint32_t mask_r2 = ((struct route_table_entry *)q)->mask; 
         return mask_r2 - mask_r1;
    }
    //ordonez dupa prefix
    return prefix_r2 - prefix_r1;
}



int main(int argc, char *argv[]) {

	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);
	
	//aloc tabela de rutare
	rtable = malloc(sizeof(struct route_table_entry) * 65000);
	DIE(rtable == NULL, "memory");
	
	//aploc tabela arp - ori o citesc din fisier ori o compun eu.
	arp_table = malloc(sizeof(struct  arp_entry) * 500);
	DIE(arp_table == NULL, "memory");

    
        //citesc in tabela de rutare
        rtable_size = read_rtable(argv[1], rtable);
        //printf("%d\n\n", rtable_size);
	//arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	//qsort((void*)rtable, rtable_size, sizeof(struct route_table_entry), comparator);

        for(int i = 0; i < rtable_size; i ++) {
        struct in_addr a;
                a.s_addr =  rtable[i].prefix;
                
                printf("ip : %s \n", inet_ntoa(a));
        }
	
        char* ip = calloc(20, sizeof(char));
        uint8_t mac_m[6];
        int nr_pcks = 5; //nu pot sa am mai mult de 5 pachete netransmise.
        packet p;
        
        //vector de pointeri la pachete
        packet** pcks = malloc(nr_pcks * sizeof(packet*));
        for(int i = 0; i < nr_pcks; i ++) {
                pcks[i] = malloc(sizeof(packet));
        }
        //vector de pozitii ocupate in cadrul vectorului de pachete. 
        int* ocupat = calloc(nr_pcks, sizeof(int));
        int add_r = 0;
        arp_table_len = 0;
        
       // printf("sizeof(struct ether_header)   %ld\n", sizeof(struct ether_header))   ; 
        // printf("sizeof(struct iphdr)   %ld\n", sizeof(struct iphdr))   ; 
        //printf("sizeof(struct icmphdr)   %ld\n", sizeof(struct icmphdr))   ; 

        //primesc pachete
	while (1) {

		rc = get_packet(&m);
		DIE(rc < 0, "get_packet?");
		
		//extrag headerul de ethernet, toate pachetele primite au acest header.
		struct ether_header *eth = (struct ether_header *) ((void *)m.payload);
		struct iphdr *iph;
		struct icmphdr *icmph;
		struct in_addr dest_ip;
		struct arp_header* arph;
		
		//adresa ip a routerului reprezentata ca string
		memset(ip, 0, 20);
		ip = get_interface_ip(m.interface); 
		
		//adresa ip in network byte order
		struct in_addr ip_m; 
		inet_aton(ip, &ip_m);
		
		//adresa mac a routerului
		get_interface_mac(m.interface, mac_m); 
		
                //la primul pacht primit se actualizeaza tabela arp cu ip-mac ale ruterului. 
		
                //adaug intrare si pt ruter.
                if(add_r == 0) {
                        arp_table[arp_table_len].ip = ip_m.s_addr;
                        memcpy(arp_table[arp_table_len].mac, mac_m, 6);
                        arp_table_len++;
                        add_r = 1;
                }
                //curat bufferul
                memset(&p, 0, 1608);
                p.interface = m.interface; //pe ce interfata timit pachetul
               
                //trebuie sa verific dc pachetul e pt router sau pt toata lumea
                int ok_b = 0; //dc adresa destinatie este chiar adresa broadcast
                for(int i = 0; i < 6; i ++) {
                        if(eth->ether_dhost[i] == 0xff)
                                ok_b++;
                        else break;
                }

               int ok_d = 0; //sau dc adresa mac destinatie corespunde cu adresa ruterului.
               for(int i = 0; i < 6; i ++) {
                        if(mac_m[i] == eth->ether_dhost[i])
                                ok_d++;
                        else break;
               }
               
               //dc nu e nici arp, nici ip trebuie aruncat.
               if ((ntohs(eth->ether_type) != 0x0806) && (ntohs(eth->ether_type) != 0x0800)) continue; 

	        //verific sa vad dc am un pachet ARP incapsulat
                if (ntohs(eth->ether_type) == 0x0806) {

                         //extrag header arp, verific tipul
                         arph = (struct arp_header*)((void *)m.payload + sizeof(struct ether_header));

                        if(ntohs(arph->op) == 1) { //request
                         
                                //dc pachetul nu e nici pt router, nici pentru toata lumea, nu trebuie sa raspund
                                if((ok_d != 6) && (ok_b != 6)) continue;

                                //e request, trimit inapoi de unde a venit pachetul un arp replay
                                struct ether_header *eth2 = calloc(1, sizeof(struct ether_header));    

                               //completez adresa mac a destinatiei cu adresa mac a sursei
                                memcpy(eth2->ether_dhost, eth->ether_shost, 6);
                                //completez headerul arp - campul adresei mac sursa cu macul routerului
                                memcpy(eth2->ether_shost, mac_m, 6); 
                                eth2->ether_type = htons(0x0806); //transporta un arp

                                //fac ac lucru si pentru headerul de ip, dar completez cu adresele ip
                                struct arp_header* arp2 = calloc(1, sizeof(struct arp_header));
                                memcpy(arp2->tha, arph->sha, 6);
                                memcpy(arp2->sha, mac_m, 6); 
                                
                                arp2->tpa = arph->spa;
                                arp2->spa = ip_m.s_addr;                              
                                arp2->op = htons(2); //replay
                                
                                //trebuie completate si lungimile
                                arp2->htype = arph->htype;
	                        arp2->ptype = arph->ptype;
	                        arp2->hlen = arph->hlen;
	                        arp2->plen = arph->plen;
                                
                                //formez pachetul cu headerele de mai sus ether + arp-replay,
                                memset(&p, 0, 1608);
                                memcpy(p.payload, eth2, sizeof(struct ether_header));
                                memcpy(p.payload + sizeof(struct ether_header), arp2, sizeof(struct arp_header));
                                p.len = sizeof(struct ether_header) + sizeof(struct arp_header);
                                
                                p.interface = m.interface;
                                //print(p);
                                send_packet(&p);
                                
                                continue;
                         }
                        if(ntohs(arph->op) == 2) { //replay
                                
                                //adaug intrare in tabela.
                                arp_table[arp_table_len].ip = arph->spa;
                                memcpy(arp_table[arp_table_len].mac, arph->sha, 6);
                                arp_table_len++;
                                
                                //trec prin pachetele salvate sa vad dc pot trimite vreunu dintre ele, acum ca mai am o intrare in tbela arp
                                for(int i = 0; i < nr_pcks; i++) {
                                
                                        if(ocupat[i] == 0) continue;
                                        //printf("deci am gasit un mac si acum trimit pachet \n\n");
                                        //print(*pcks[i]);
                                        
                                        //daca am pachete netrimise, incerc sa le trimit; extrag hederele
                                        struct ether_header * eth_r = (struct ether_header *) ((void *)pcks[i]->payload);
                                        struct iphdr *iph_r = (struct iphdr *)((void *)pcks[i]->payload + sizeof(struct ether_header));

                                        iph_r->ttl--;
                                        iph_r->check = 0;
                                        iph_r->check = ip_checksum((void *) iph, sizeof(struct iphdr));
                                                        
                                        //caut sa vad cea mai buna ruta pentru a trimit pachetul.                
                                        dest_ip.s_addr = iph_r->daddr;
                                        struct route_table_entry *route = get_best_route(dest_ip); 
                                        
                                        //nu fac nimic dc nu gasesc ruta, doar eliberez vectorul de pachetul aruncat.
                                        if(route == NULL) {
                                                ocupat[i] = 0;
                                                memset(pcks[i], 0, 1608);
                                                continue;
                                        }
                                        dest_ip.s_addr = route->next_hop; //caut urmatorul hop
                                        struct arp_entry *arp = get_arp_entry(dest_ip); //caut adresa mac a urmatorului hop
                                        
                                        //dc nu am gasit adresa ip in tabela, nu fac nmic.
                                        if(arp == NULL) continue;
                                        
                                        //il pot trimite si copmletez de unde il trimit si unde.
                                        memcpy(eth_r->ether_shost, mac_m, 6); 
                                        memcpy(eth_r->ether_dhost, arp->mac, 6);
                                       
                                        //completare pachet cu datele madificate(de mai sus).
                                        memset(&p, 0, 1608); 
                                        memcpy(p.payload, eth_r, sizeof(struct ether_header)); 
                                        int diff = sizeof(struct ether_header) + sizeof(struct iphdr);
                                        memcpy(p.payload + sizeof(struct ether_header), iph_r, sizeof(struct iphdr));
                                        //copiez si orice era dupa ip
                                        memcpy(p.payload + sizeof(struct ether_header) + sizeof(struct iphdr), pcks[i]->payload + diff, 1600 - diff);

                                        p.len = pcks[i]->len;
                                        p.interface = route->interface;
                                        
                                        send_packet(&p);
                                        //printf("seg 10\n");
                                        
                                        //eliberez pozitia si curat bufferul.
                                        ocupat[i] = 0;
                                        memset(pcks[i], 0, 1608);
                           
                                }           

                                continue;
                        }
                //dc nu e request sau replay, nu fac nimic cu pachetul.
                continue;
                }
               
                //altfel am incapsulat in headerul ether un ip.
                //extrag headerul ip
                iph = (struct iphdr *)((void *)m.payload + sizeof(struct ether_header)); 
                //extrag headerul de icmp din pachet, e dupa headerele de ether si ip.

                //se da drop pachetului daca nu are checksumul ok
                if (ip_checksum((void *) iph, sizeof(struct iphdr)) != 0) {
                        continue;
                }
                
                //pachet expirat
                if (iph->ttl <= 1) {
                        //printf("unde 1 icmp ttl<< \n");  
             
                        //inversez adresele mac
                        struct ether_header *eth2 = calloc(1, sizeof(struct ether_header));        
                        memcpy(eth2->ether_dhost, eth->ether_shost, 6);
                        memcpy(eth2->ether_shost, mac_m, 6); 
                        eth2->ether_type = htons(0x0800); //transporta un ip

                        //compun un header de ip si completez campurile
                        struct iphdr* iph2 = calloc(1, sizeof(struct iphdr));
                        iph2->daddr = iph->saddr; 
                        //il timit de pe router pt ca nu i se gaseste o ruta de transmitere.
                        iph2->saddr = ip_m.s_addr;
                        iph2->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
                        iph2->protocol = 1;
                        
                        //compun headerul de icmp(time exceeded)
                        struct icmphdr* icmph2 = calloc(1, sizeof(struct icmphdr));
                
                        icmph2->code = 0;
                        icmph2->type = 11;
                      
                        //caclculez si checksumul fiecarui header
                        icmph2->checksum = 0;
                        icmph2->checksum = icmp_checksum((void *) icmph2, sizeof(struct icmphdr));
                        
                        iph2->version = 4;
                        iph2->ttl = iph->ttl;
                        iph2->check = 0;
                        iph2->check = ip_checksum((void *) iph2, sizeof(struct iphdr));

                       //pun in paloadyl pachetului in ordine headeul de ether, ip, icmp si cei 64 de octeti ceruti.
                        int diff = sizeof(struct ether_header) + sizeof(struct iphdr);
                        memcpy(p.payload, eth2, sizeof(struct ether_header));
                        memcpy(p.payload + sizeof(struct ether_header), iph2, sizeof(struct iphdr));
                        memcpy(p.payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmph2, sizeof(struct icmphdr));
                        memcpy(p.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), m.payload + diff, 64);
                        p.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);// + 64;
                     
                        //trimti inapoi pe unde a venit
                        p.interface = m.interface; 
   
                        //print(p);       
                        send_packet(&p);
                        continue;
                }

                //pachetul ii e destinat routerului
                if(ip_m.s_addr == iph->daddr) { 
                        //printf("aci trebuie sa ajunga icmph->type %d \n", ntohs(icmph->type));  

                        //iau adresele mac din ether_hdr si le pun in eth2 inversate
                        struct ether_header *eth2 = calloc(1, sizeof(struct ether_header));        
                        memcpy(eth2->ether_dhost, eth->ether_shost, 6);
                        memcpy(eth2->ether_shost, eth->ether_dhost, 6); 
                        eth2->ether_type = htons(0x0800); //transporta un ip

                        //creez un header nou de ihhdr si il populez cu datele din headerul de ip al pachetului
                        //primit, am grija sa completez bine ip destinaite si ip sursa. 
                        struct iphdr* iph2 = calloc(1, sizeof(struct iphdr));
                        iph2->daddr = iph->saddr; 
                        //il timit de pe router pt ca nu i se gaseste o ruta de transmitere.
                        iph2->saddr = ip_m.s_addr;
                        iph2->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
                        iph2->protocol = 1;
             
                        //creez echo replay.
                        struct icmphdr* icmph2 = calloc(1, sizeof(struct icmphdr));
                        icmph = (struct icmphdr *)((void *)m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
                        
                        //trebuie sa fie echo request, altfel nu am de ce sa trimit echo replay inapoi
                        if(icmph->type != 8) continue;
                        
                        //aici aveam probleme, deci copiez tot ce e in icmp-ul din pachetul primit si
                        //doar mai modific tipul si checksumul.
                        memcpy(icmph2, icmph, sizeof(struct icmphdr));

                        icmph2->code = 0;
                        icmph2->type = 0; //echo - replay.
                        icmph2->checksum = 0;
                        icmph2->checksum = icmp_checksum((void *) icmph2, sizeof(struct icmphdr));

                        //actualizez pt headerul ip suma de control
                        iph2->ttl--;
                        iph2->check = 0;
                        iph2->check = ip_checksum((void *) iph2, sizeof(struct iphdr));

                        //formez pachetul
                        memset(&p, 0, 1608);
                        //adaug pe rand headerele eherne + ip + icmp;
                        memcpy(p.payload, eth2, sizeof(struct ether_header));
                        memcpy(p.payload + sizeof(struct ether_header), iph2, sizeof(struct iphdr));
                        memcpy(p.payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmph2, sizeof(struct icmphdr));
                        
                        //adaug si ce era in pachetul original dupa icmp
                        int diff = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
                        memcpy(p.payload + diff, m.payload + diff, 1600 - diff);
                        
                        p.len = m.len;
                        p.interface = m.interface; //trimit pe interfata pe care a venit.

                        send_packet(&p);

                        continue;

                }

                //dc nu e destinat routerului, atunci incerc sa il trimit mai departe.
                dest_ip.s_addr = iph->daddr;
                struct route_table_entry *route = get_best_route(dest_ip); 
                //daca nu gasesc o ruta, atunci trimit icmp-error(dest unreachable)
                if (route == NULL) {
                        //printf("unde 5 rt negasita\n");
                        //compun un headere de ether si completez adresele mac(trimit invers)
                        struct ether_header *eth2 = calloc(1, sizeof(struct ether_header));        
                        memcpy(eth2->ether_dhost, eth->ether_shost, 6);
                        memcpy(eth2->ether_shost, eth->ether_dhost, 6); 
                        eth2->ether_type = htons(0x0800); //incapsulez un header ip

                        //creez un header ip care contine un header icmp
                        struct iphdr* iph2 = calloc(1, sizeof(struct iphdr));
                        //vreau sa il timit inapoi de unde a venit
                        iph2->daddr = iph->saddr; 
                        //il timit de pe router pt ca nu i se gaseste o ruta de transmitere.
                        iph2->saddr = ip_m.s_addr;
                        //headerul ip e format din headerul ip + headerul icmp + 64 octeti din mesajul initial.
                        iph2->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
                        //trimit incpasulat in headerul de ip, unul de icmp
                        iph2->protocol = 1;
                        
                        //formez headerul si completez corespunzator.
                        struct icmphdr* icmph2 = calloc(1, sizeof(struct icmphdr));
                        icmph2->code = 0;
                        icmph2->type = 3;
                        
                        //calculez si checksumurile pt icmp si ip
                        icmph2->checksum = 0;
                        icmph2->checksum = icmp_checksum((void *) icmph2, sizeof(struct icmphdr));
                        
                        iph2->ttl--;
                        iph2->check = 0;
                        iph2->check = ip_checksum((void *) iph2, sizeof(struct iphdr));

                        //pun totul in pachet si il trimit inapoi
                        int diff = sizeof(struct ether_header) + sizeof(struct iphdr);
                        memcpy(p.payload, eth2, sizeof(struct ether_header));
                        memcpy(p.payload + sizeof(struct ether_header), iph2, sizeof(struct iphdr));
                        memcpy(p.payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmph2, sizeof(struct icmphdr));
                        //pun si cei 64 de octeti din pachetul(payloadul) initial, cei de dupa headerul ip.
                        memcpy(p.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), m.payload + diff, 64);
                        p.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);// + 64;
                     
                        //trimit pe unde a venit.
                        p.interface = m.interface;
                        send_packet(&p);
                        //trec la uramtorul pachet
                        continue;
                }
                

                //incerc sa gasesc adresa mac care corespunde adresei ip a next hopului.
                dest_ip.s_addr = route->next_hop; //comp cu adresa ip
                struct arp_entry *arp = get_arp_entry(dest_ip); 
                //interfata pe care trebuie trimis pachetul
                p.interface = route->interface;

                if (arp == NULL) {
                        //trebuie sa adug in vector pachetul pe care nu am putut sa il 
                        for(int i = 0; i < nr_pcks; i ++) {
                                //caut un loc pt pachet si il copiez.         
                                if(ocupat[i] == 0) { //adaug pachetul in vector.
                                        memcpy(pcks[i], &m, sizeof(packet));
                                        //printf("am vreodata seg");
                                        ocupat[i] = 1;
                                        break;
                                }  
                        }

                        //transmit si trimit arp_request broadcast.
                        memcpy(eth->ether_shost, mac_m, 6); 
                        //trimit catre toate dispozitivele conectate la router
                        eth->ether_dhost[0] = 0xff;
                        eth->ether_dhost[1] = 0xff;
                        eth->ether_dhost[2] = 0xff;
                        eth->ether_dhost[3] = 0xff;
                        eth->ether_dhost[4] = 0xff;
                        eth->ether_dhost[5] = 0xff;

                        //trimit un header de arp dupa cel de ethernet.
                        eth->ether_type = htons(0x0806);

                        //inceputul payloadului contine headerul de ethernet
                        
                        //creez headerul arp
                        struct arp_header* arph = calloc(1, sizeof(struct arp_header));

                        arph->tpa = iph->daddr; //completez adresa ip a destinaitei
                        arph->spa = ip_m.s_addr; //adresa ip a routerului

                        memcpy(arph->sha, mac_m, 6);
                        memcpy(arph->tha, eth->ether_dhost, 6);
                        arph->op = htons(1); //request

                        arph->htype = htons(1);
	                arph->ptype = htons(2048);
	                
	                arph->hlen = 6;
	                arph->plen = 4;
                        
                        //aduag headerele, setez lungimea si interfata pe care timit
                        memset(&p, 0, 1608);
                        memcpy(p.payload, eth, sizeof(struct ether_header));
                        memcpy(p.payload + sizeof(struct ether_header), arph, sizeof(struct arp_header));
                        p.len = sizeof(struct ether_header) + sizeof(struct arp_header);
                        p.interface = route->interface;
                        
                        //printf("AM TRIMIS CE TREBUIA SA TRIMIT\n\n");
                        //print(p);
                        send_packet(&p);
                        
                        //trec la urmatorul pachet
                        continue;
                } 
                else { //daca am adresa mac a destinatiei, atunci transimit pachetul
                        
                        //if(iph->saddr == iph->daddr) continue;
                        //pot sa transmit pachetul, deci actuaizez informatiile despre adresele: sursa si destinatie
                        memcpy(eth->ether_dhost, arp->mac, 6);
                        memcpy(eth->ether_shost, mac_m, 6); //sau eth->ether_dhost
                        eth->ether_type = eth->ether_type;
           
                        //actualizez suma de control
                        iph->ttl--;
                        iph->check = 0;
                        iph->check = ip_checksum((void *) iph, sizeof(struct iphdr));
                       
                        
                        //adaug headerul de eth cu adresele mac schimbate + headerul de ip cu modificarea checksumului
                        memcpy(p.payload, eth, sizeof(struct ether_header));
                        memcpy(p.payload + sizeof(struct ether_header), iph, sizeof(struct iphdr));
                        
                        //adaug si restul pachetului - tot ce se afla dupa headerul ip.
                        int diff = sizeof(struct ether_header) + sizeof(struct iphdr);
                        memcpy(p.payload + sizeof(struct ether_header) + sizeof(struct iphdr), m.payload + diff , m.len - diff);
                         
                        //completez lungimea pachetului si interfata pe care il trimit.
                        p.len = m.len;//diff + 64;
                        p.interface = route->interface;

                        //print(p);
                        send_packet(&p);

                        continue;
                }
        }
}