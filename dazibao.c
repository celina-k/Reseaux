
#include "dazibao.h"

int creation_socket(){
	int so = socket(AF_INET6, SOCK_DGRAM, 0);
	if(so<0) {
		perror("Échec socket");
		abort();
	}

    int rc = fcntl(so, F_GETFL);
    if(rc < 0) {
        perror("Échec fcntl");
        abort();
    }
    rc = fcntl(so, F_SETFL, rc | O_NONBLOCK);
    if(rc < 0) {
        perror("Échec fcntl");
        abort();
    }

    int val = 0 ;
	rc = setsockopt(so, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	if(rc!=0)
	{
		perror("Échec setsockopt ");
		abort();
	}

	val = 1 ;
	rc = setsockopt(so, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if(rc!=0)
	{
		perror("Échec setsockopt ");
		abort();
	}

    struct sockaddr_in6 sin6;
    memset (&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(1354);

    rc = bind (so, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc<0){
        perror("Échec bind");
        abort();
    }
    
	return so ;
}



int add_neighbour (struct sockaddr_in6 *addr, int permanent){
    if (NEIGH_CAPACITY==neighTable.len) {
        return -1;
    }
    neighbour n ;
    n.sin = addr;
    n.permanent=permanent;
    time(&n.last_package);
    neighTable.table[neighTable.len] = n;
    neighTable.len += 1 ;
    return neighTable.len-1;
}


int getneighbour (struct sockaddr_in6* sin6) {
    int i ;
    for(i=0; i<neighTable.len; i++){
    	 if ((memcmp(neighTable.table[i].sin->sin6_addr.s6_addr,
    	         sin6->sin6_addr.s6_addr,
    	         16)==0 ) && memcmp(&neighTable.table[i].sin->sin6_port,&sin6->sin6_port,2) == 0)
            return i;
    }
    return -1;
}



char * paquet_ok (unsigned char * reply, size_t len){
    if(reply[0]!=95)
        return "Magic incorrect";
    if(reply[1]!=1)
        return "Version incorrecte";
    unsigned short package_len = 0;
    memcpy(&package_len, reply+2, 2);
    package_len = ntohs(package_len) +4;
    if (package_len != len || package_len < 4 || package_len > 1024 ){
        return "Taille de paquet incorrecte";
    }
    unsigned char* current_tlv = reply+4;
    while (current_tlv<(reply+package_len)){
        current_tlv += current_tlv[1]+2;
    }

    if ( current_tlv - reply != package_len ) {
        return "Taille de TLV incorrecte";
    }

    return "";
}


long getData ( uint64_t id ){
    data* table = dataTable.table;
    data* start = table;
    data* end = table+dataTable.len-1;
    data* current;
    do  {
        current = start + (end-start)/2 ;
        if (current->node_id < id)
            start = current + 1 ;
        else
            end = current - 1 ;
    }
    while ( current->node_id!=id && end >= start );
    if ( current->node_id == id )
        return current-table;
    else 
        return start-table;
}

void swap(tlv* a, tlv* b)
{
    tlv t = *a;
    *a = *b;
    *b = t;
}

int partition (tlv arr[], int low, int high)
{
    int pivot = arr[high].length;
    int i = (low - 1);
    int j;
    for (j = low; j <= high- 1; j++)
    {
        if (arr[j].length < pivot)
        {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return (i + 1);
}

void quickSort(tlv arr[], int low, int high)
{
    if (low < high)
    {
        int pi = partition(arr, low, high);
        quickSort(arr, low, pi - 1);
        quickSort(arr, pi + 1, high);
    }
}



void insertData ( data to_add ) {
    long index = getData(to_add.node_id);
    data *dat = dataTable.table + index;

    if (dat->node_id == to_add.node_id) {
        if (memcmp(dat->node_hash, to_add.node_hash, 16) != 0) {
            if (index == ourdata_index) {
                data *our_data = dataTable.table + ourdata_index;
                if (((to_add.seq - our_data->seq) & 32768) == 0){
                    our_data->seq = (to_add.seq + 1) & 65535;
                    updated_our_data=0;
                    updated_our_network=0;
                }
                free(to_add.d);
            }

            else if (((dat->seq - to_add.seq) & 32768) != 0) {
                memcpy(dat->node_hash, to_add.node_hash, 16);
                dat->seq = to_add.seq;
                if(dat->len<to_add.len){
                		unsigned char * newData = realloc(dat->d, to_add.len);
                		if(newData!=NULL) {
                            dat->d = newData;
                            perror("Échec de realloc");
                            exit(1);
                        }
                }
                memcpy(dat->d, to_add.d, to_add.len);
                dat->len = to_add.len;
                updated_our_network=0;
                free(to_add.d);
            }

        }

    } else {
            updated_our_network=0;
            if (dataTable.len == dataTable.capacity) {
                void *newTable = realloc(dataTable.table,
                                         (dataTable.capacity +100 )* sizeof(data));
                if (newTable != NULL) {
                    dataTable.table = newTable;
                    dataTable.capacity = dataTable.capacity+100;
                }
                else {
                    perror("Échec de realloc");
                    exit(1);
                }
            }
            dat = dataTable.table + index;
            if (index <= ourdata_index)
                ourdata_index += 1;
            memmove(dat + 1, dat, (dataTable.len - index) * sizeof(data));
            memcpy(dat, &to_add, sizeof(data));
            dataTable.len += 1;
        }
    }

     
void data_hash (uint64_t id, uint16_t seq, unsigned char *data, size_t data_len, unsigned char *node_hash){

    size_t id_len = 8;
    size_t seq_len = 2;
    size_t d_len = data_len;
    size_t len = id_len + seq_len + d_len ;
    unsigned char * triplet = malloc(len);
    if (triplet == NULL) {
        perror("Échec de malloc");
        exit(1);
    }
    uint16_t true_seq = htons(seq);

    memcpy(triplet, &(id), id_len);
    memcpy(triplet+id_len, &(true_seq), seq_len);
    memcpy(triplet+id_len+seq_len, data, d_len);

    SHA256Context ctx;
    memset(&ctx,0, sizeof(SHA256Context));
     unsigned char hash[32];
    int rc = SHA256Reset(&ctx);
    if(rc<0){
        perror("SHA256Reset échec");
        return;
    }

    rc = SHA256Input(&ctx, triplet, len);
    if(rc<0){
        perror("SHA256Input échec");
        return;
    }

    rc = SHA256Result(&ctx, hash);
    if(rc!=0){
        perror("SHA256Result échec");
        return;
    }

    memcpy(node_hash, hash, 16);

    free(triplet);
}

void update_our_data_hash () {
   if (updated_our_data==0) {
        data *ourdata = dataTable.table + ourdata_index;
        data_hash(ourdata->node_id, ourdata->seq, ourdata->d, ourdata->len,
                  ourdata->node_hash);
     updated_our_data=1;
    }
}

unsigned char* network_hash (){
    if (updated_our_network==1)
        return dataTable.hash;
    update_our_data_hash();
    size_t to_hash_len = (dataTable.len)*16;
    unsigned char * concat_hash = malloc(to_hash_len);
    if(concat_hash==NULL) {
         perror("Échec malloc\n");
         exit(1);
    }
    int i ;
    data* curr = dataTable.table;
    unsigned char* curr_hash = concat_hash;
    for(i=0; i<dataTable.len; i++){
        memcpy(curr_hash, curr->node_hash, 16);
        curr += 1;
        curr_hash+=16;
    }
    SHA256Context ctx;
    unsigned char hash[32];
    SHA256Reset(&ctx);
    SHA256Input(&ctx, concat_hash, to_hash_len);
    SHA256Result(&ctx, hash);
    memmove(dataTable.hash, hash, 16);
    free(concat_hash);
    updated_our_network=1;
    return dataTable.hash;
}



int header_builder (unsigned char* header,unsigned short length){
    memset(header, 0, 4);
    short body_length = htons(length) ;

    header[0]=95;
    header[1]=1;
    memcpy(header+2, &body_length,2);
    return 4;
}

int tlv_pad_n (tlv tlv, unsigned char* buf){
    int n = tlv.pad;
    if (n==1){
        buf[0]=0;
    }
    else {
        buf[0] = 1;
        buf[1] = n-2;
        memset(buf,0,n-2);
    }
    return n;
}

int tlv_neighbour_request (tlv tlv,unsigned char* buf)
{
    buf[0]=2;
    buf[1]=0;
    return 2;
} 

int tlv_neighbour (tlv tlv, unsigned char* buf) {
    memset(buf,0,20);
    srand(time(NULL));
    int ind = rand()%(neighTable.len);
    struct sockaddr_in6* sin6 = neighTable.table[ind].sin;
    unsigned char* ip = sin6->sin6_addr.s6_addr;
    short port = sin6->sin6_port;
    buf[0]=3;
    buf[1]=18;
    memcpy(buf+2,ip,16);
    memcpy(buf+18,&port,2);
    return 20;
}

int tlv_network_hash (tlv tlv, unsigned char* buf ) {
    memset(buf,0,18);
    buf[0]=4;
    buf[1]=16;
    memcpy(buf+2,dataTable.hash,16);
    return 18;
}



int tlv_network_state_request (tlv tlv, unsigned char* buf) {
    memset(buf,0,2);
    buf[0]=5;
    buf[1]=0;
    return 2;
}

int tlv_node_hash (tlv tlv, unsigned char* buf) {

    memset(buf,0,28);
    buf[0]=6;
    buf[1]=26;
    memcpy(buf+2,&tlv.node_id,8);
    if (tlv.length==26) {
        memcpy(buf+10,&tlv.seqno,2);
        memcpy(buf+12,tlv.hash,16);
    }
    else {
        long index = getData(tlv.node_id);
        data d = dataTable.table[index] ;
        memcpy(buf+10,&d.seq,2);
        memcpy(buf+12,d.node_hash,16);
    }
    return 28;
}

int tlv_node_state_request (tlv tlv, unsigned char* buf) {
    long id = tlv.node_id;
    memset(buf,0,10);
    buf[0]=7;
    buf[1]=8;
    memmove(buf+2,&id,8);
    return 10;
}

int tlv_node_state (tlv tlv, unsigned char* buf) {
    buf[0]=8;
    if (tlv.length==0) {
        long index = getData(tlv.node_id);
        data d = dataTable.table[index];
        buf[1]=d.len + 26 ;
        memcpy(buf+2,&d.node_id,8);
        memcpy(buf+10,&d.seq,2);
        memcpy(buf+12,d.node_hash,16);
        memcpy(buf+28,d.d,d.len-28);
    }
    else {
        buf[1]=tlv.length;
        memcpy(buf+2,&tlv.node_id,8);
        memcpy(buf+10,&tlv.seqno,2);
        memcpy(buf+12,tlv.hash,16);
        memcpy(buf+28,tlv.data,tlv.data_len);
    }
    return buf[1]+2;
}



int tlv_warning (tlv tlv, unsigned char* buf){
    unsigned char* message = tlv.data;
    unsigned char message_len = tlv.data_len;
    memset(buf, 0, message_len+2);
    buf[0] = 9;
    buf[1] = message_len;
    memmove(buf+2, message, message_len);
    return message_len +2 ;
}

int (*tlv_builder[10])(tlv x,unsigned char* buf) =
            /*0*/    {tlv_pad_n,
          /*1*/       tlv_pad_n,
          /*2*/      tlv_neighbour_request,
          /*3*/      tlv_neighbour,
          /*4*/     tlv_network_hash,
          /*5*/    tlv_network_state_request,
          /*6*/    tlv_node_hash,
          /*7*/    tlv_node_state_request,
          /*8*/    tlv_node_state,
        /*9*/      tlv_warning};


int return0 (unsigned char* current_tlv, tlv table[], int len){
	return 0 ;
}

int neighbour_request_processor( unsigned char* current_tlv, tlv table[], int len) {
    tlv t;
    t.type=3;
    t.length =  18 ;
    table[len]=t;
    return 1;
}

int neighbour_processor ( unsigned char* current_tlv, tlv table[], int len) {
    printf("Reçu un voisin ! Nombre actuel de voisins : %d\n", neighTable.len);
	if ( neighTable.len != NEIGH_CAPACITY ) {
        struct sockaddr_in6 *sin6 = malloc(sizeof(struct sockaddr_in6));
        if (sin6 == NULL) {
            perror("Échec de malloc");
            return 0;
        }
        memset(sin6, 0, sizeof(struct sockaddr_in6));
        struct in6_addr in6;
        memset(&in6, 0, sizeof(struct in6_addr));
        sin6->sin6_family = AF_INET6;
        memcpy(&in6, current_tlv + 2, 16);
        uint16_t port;
        memcpy(&port, current_tlv + 18, 2);
        sin6->sin6_port = port;
        sin6->sin6_addr = in6;
        if (getneighbour(sin6) == -1) {
            tlv t;
            t.type = 4;
            t.length = 16;
            tlv table_types[] = {t};
            package_sender(sin6, package_builder(table_types, 1));
        }
        else {
            printf("Voisin déjà connu\n");
        }
        free(sin6);
    }
    return 0;
}

int network_hash_processor (unsigned char* current_tlv, tlv table[], int len){
	unsigned char hash[16];
	memcpy(hash, current_tlv+2, 16);
	network_hash();
	if(memcmp(dataTable.hash,hash,16) != 0 ){
		tlv t;
		t.type = 5 ;
		t.length=0;
		table[len] = t ;
		return 1;
	}
	else {
	    converged=1;
        printf("On a convergé avec un voisin !\n");
    }
	return 0 ;
}

int network_state_request_processor (unsigned char* current_tlv, tlv table[], int len){
	int i;
	update_our_data_hash();
	for (i=0; i<dataTable.len; i++){
		tlv t ;
		t.type = 6 ;
        t.node_id = dataTable.table[i].node_id;
        t.length = 26 ;
		t.seqno = htons(dataTable.table[i].seq);
		memcpy(t.hash, dataTable.table[i].node_hash, 16);
		table[len+i] = t ;
	}
	return dataTable.len ;
}

int node_hash_processor(unsigned char* current_tlv, tlv table[], int len) {
    uint64_t node_id;
    unsigned short seqno;
    unsigned char node_hash[16];
    memcpy(&node_id, current_tlv + 2, 8);
    memcpy(&seqno, current_tlv + 10, 2);
    seqno = ntohs(seqno);
    memcpy(node_hash, current_tlv + 12, 16);
    data* ourdata = dataTable.table+ourdata_index;
    if (node_id == ourdata->node_id) {
        if (((seqno - ourdata->seq) & 32768) == 0){
            ourdata->seq = (seqno + 1) & 65535;
            updated_our_data=0;
            updated_our_network=0;
        }
        return 0;
    }
    long index = getData(node_id);
    data d = dataTable.table[index];
    if ((memcmp(node_hash,d.node_hash,16) != 0 && ((seqno - d.seq) & 32768) != 0) ||
        node_id != d.node_id) {
        tlv t;
        t.type = 7;
        t.length=8;
        t.node_id = node_id;
        table[len] = t;
        return 1;
    }
    return 0;
}

int node_state_request_processor  (unsigned char* current_tlv, tlv table[], int len) {
    uint64_t id;
    memcpy(&id,current_tlv+2,8);
    if (id == MYID)
        update_our_data_hash();
    long index = getData(id);
    data where = dataTable.table[index];
    if (where.node_id == id) {
        tlv t;
        t.type=8;
        t.length=where.len +26;
        t.node_id=id;
        t.seqno=htons(where.seq);
        memcpy(t.hash,where.node_hash,16);
        t.data=where.d;
        t.data_len=where.len;
        table[len]=t;
        return 1;
    }
    return 0;
}

int node_state_processor (unsigned char* current_tlv, tlv table[], int len) {
    unsigned char data_len = current_tlv[1] - 26;
    if (data_len > 192) {
        tlv t;
        t.type = 9;
        char* message = "Node State with data length > 192";
        int message_len = strlen(message);
        t.data = (unsigned char* ) message;
        t.data_len = message_len;
        t.length= message_len;
        table[len] = t;
        return 1;
    }
    data d;
    memcpy(&(d.node_id), current_tlv + 2, 8);
    memcpy(&(d.seq), current_tlv + 10, 2);
    d.seq = ntohs(d.seq);
    memcpy(d.node_hash, current_tlv + 12, 16);
    d.len = data_len;
    d.d = malloc(data_len);
    memcpy(d.d, current_tlv + 28, data_len);
    unsigned char ourhash[16];
    data_hash(d.node_id, d.seq, d.d, d.len, ourhash);
    if (memcmp(d.node_hash, ourhash, 16) == 0) {
        insertData(d);
    }
    else{
        tlv t;
        t.type=9;
        char* message = " Node hash non cohérent avec les données";
        size_t message_len = message_len;
        t.length=message_len;
        t.data= (unsigned char*)message;
        table[len]=t;
        free(d.d);
        return 1;
    }
    return 0;
}

int warning_processor(unsigned char* current_tlv, tlv table[], int len) {
    char * string = malloc(current_tlv[1] + 1 );
     if(string==NULL) {
         printf("Échec malloc\n");
         exit(1);
     }
    memcpy(string, &current_tlv[2], current_tlv[1]);
    string[current_tlv[1] + 1 ] = '\0';
    printf("############################ Message TLV Warning : %s\n",string);
    free(string);
    return 0;
}


int (*tlv_processor[10])(unsigned char* current_tlv, tlv table[], int len) = 
{
	/*O*/ return0,
	/*1*/ return0,
	/*2*/ neighbour_request_processor,
	/*3*/ neighbour_processor,
	/*4*/ network_hash_processor,
	/*5*/ network_state_request_processor,
	/*6*/ node_hash_processor,
	/*7*/ node_state_request_processor,
	/*8*/ node_state_processor,
	/*9*/ warning_processor,
};						


unsigned char* package_builder (tlv table[], unsigned int amount_of_tlv) {
    unsigned char* package = malloc(1024);
    if(package==NULL) {
        printf("Échec de malloc\n");
        abort();
    }

    memset(package,0,1024);
    int offset = 0;
    unsigned char* current = package;
    int i;
    for ( i = 0; i < amount_of_tlv; i++) {
        offset = tlv_builder[table[i].type](table[i],current);
        current += offset;
        }

    unsigned short body_length = current-package;

    unsigned char* temp = malloc(body_length+4);
    if(temp==NULL) {
        printf("Échec malloc\n");
        exit(1);
    }
    memset(temp,0,body_length+4);
    header_builder(temp,body_length);
    memmove(temp+4,package,body_length);
    free(package);
    return temp;
    }



int package_sender (struct sockaddr_in6* sin6, unsigned char* package) {
    short package_len = 0;
    memcpy(&package_len, package+2, 2);
    package_len = ntohs(package_len) +4;

    size_t sin6len = sizeof(struct sockaddr_in6);
    int rc;
    again :
    rc = sendto(s, package, package_len, 0, sin6, sin6len);
    if (rc == -1) {
        if (errno == EAGAIN) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(s, &writefds);
            select(s + 1, NULL, &writefds, NULL, NULL);
            goto again;
        } else {
        	free(package);
        	char ip[17];
        	memcpy(ip,&sin6->sin6_addr,16);
        	ip[16]='\0';
        	printf("Échec d'envoi de l'envoi d'un paquet à %s, au numéro de port %hu\n",ip,sin6->sin6_port);
            return 0;
        }
    }

    free(package);
    return rc;
}

void send_neigh_request (struct sockaddr_in6* addr ){
    printf("Envoyé une demande de voisin\n");
    tlv neigh_request;
    neigh_request.length = 0;
    neigh_request.type=2;
    tlv table[] = {neigh_request};
    unsigned char * package = package_builder(table,1);
    package_sender(addr,package);
}

void send_warning (struct sockaddr_in6* addr, char* error) {
    printf("Envoi d'un warning : \"%s\" au voisin %d\n",error,getneighbour(addr));;
    size_t error_len = strlen(error);
    tlv warn;
    warn.type=9;
    warn.data= (unsigned char*)error;
    warn.data_len=error_len;
    tlv table[] = {warn};
    unsigned char* package = package_builder(table,1);
    package_sender(addr,package);
}

void initialisation (char* node, char* service){
    void* memory = malloc(INITIAL_DATA_CAPACITY* sizeof(data));
    if(memory==NULL) {
        printf("Échec de malloc\n");
        abort();
    }
    dataTable.table=memory;
    dataTable.capacity=INITIAL_DATA_CAPACITY;
    data d;
    char* message = DEFAULT_MESSAGE;
    unsigned int message_len = strlen(message);
    d.d = malloc(message_len);
    memcpy(d.d,message,message_len);
    d.len=message_len;
    d.seq=INITIAL_SEQNO;
    d.node_id=MYID;
    updated_our_network=0;
    updated_our_data=0;
    converged=0;
    data_hash (d.node_id, d.seq, d.d, d.len, d.node_hash);

    dataTable.table[0]=d;
    ourdata_index = 0 ;
    dataTable.len = 1;
    network_hash();
    struct addrinfo hints ;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6 ;
    hints.ai_socktype = SOCK_DGRAM ;
    hints.ai_flags = AI_V4MAPPED | AI_ALL ;
    hints.ai_protocol = 0 ;
    int rc ;
    rc = getaddrinfo(node, service, &hints, &res);
    if(rc!=0) {
        rc = getaddrinfo("jch.irif.fr", "1212", &hints, &res);
        if (rc != 0) {
            fprintf(stderr, "Erreur getaddrinfo\n");
            exit(1);
        }
    }
    struct addrinfo *p;
    for( p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
        memmove(addr, (struct sockaddr_in6*) p->ai_addr, sizeof(struct sockaddr_in6) );
        add_neighbour( addr, 1 );
        send_neigh_request(addr);
    }
    freeaddrinfo(res);
    printf("Initialisation finie avec l'adresse donnée en argument\nNombre de voisins : %d\nNombre de données: %d\n", neighTable.len, dataTable.len);
    fflush(stdout);
}

void send_network_hash_to_all_neighbours() {
    network_hash();
    printf("Envoi d'un network hash à tous mes voisins\n");
    tlv t;
    t.type = 4;
    tlv types[] = {t};
    unsigned char* package;
    int i;
    for (i =0; i<neighTable.len ; i++) {
        package = package_builder(types,1);
        package_sender(neighTable.table[i].sin,package);
    }
}


int main (int argc, char *argv[]) {
    printf("Quittez le programme en entrant \"q\"\n");
    s = creation_socket();
    char *node = "";
    char *service = "";
    if (argc > 2) {
        node = argv[1];
        service = argv[2];
    }
    initialisation(node, service);
    unsigned char received[1024];
    memset(received, 0, 1024);
    time(&lastping);
    time_t now;
    start :
    while (1) {
        time(&now);
        if (difftime(now, lastping) > 20) {
            send_network_hash_to_all_neighbours();
            if (neighTable.len < 5) {
                srand(time(NULL));
                int ind = rand() % (neighTable.len);
                struct sockaddr_in6 *addr = neighTable.table[ind].sin;
                send_neigh_request(addr);
            }
            int i ;
            for ( i = 0; i < neighTable.len; i++) {
                neighbour *n = &neighTable.table[i];
                if (n->permanent == 0 &&
                    (difftime(now, n->last_package) > 70)) {
                    neighTable.len -= 1;
                    if (i < neighTable.len - 1)
                        memmove(n, n + 1, neighTable.len - i - 1);
                }
            }
            time(&lastping);
        }
        struct timeval t;
        t.tv_sec = 1;
        t.tv_usec = 0;
        fd_set fdreads;
        FD_ZERO(&fdreads);
        FD_SET(STDIN_FILENO, &fdreads);
        FD_SET(s, &fdreads);
        int rc = select(s + 1, &fdreads, NULL, NULL, &t);
        if (rc == -1) {
            perror("Erreur du select");
            goto start;
        } else if (rc > 0) {
            if (FD_ISSET(STDIN_FILENO, &fdreads)) {
                size_t len = read(STDIN_FILENO, received, 192);
                char *quit = "q\n";
                if (memcmp(quit, received, 2) == 0) {
                    printf("Sortie du programme\n");
                    int i;
                    for ( i = 0; i<dataTable.len; i++) {
                       printf("%lu %s\n", dataTable.table[i].node_id, dataTable.table[i].d);
                    }
                    printf("Notre numéro de sequence : %d\n",
                           dataTable.table[ourdata_index].seq);
                    printf("Notre donnée : %s\n",
                           dataTable.table[ourdata_index].d);
                    printf("Nombre de voisins connectés : %d\n",neighTable.len);
                    printf("Nombre de données récoltées : %d\n", dataTable.len);
                    if ( converged == 1)
                        printf("Nous avons convergé \\o/ ! \n");
                    else
                        printf("Nous n'avons pas eu le temps de converger :(\n");
                    return 0;
                }
                data *d = dataTable.table + ourdata_index;
                if (d->len < len) {
                    unsigned char *newData = realloc(d->d, len);
                    if (newData == NULL) {
                        perror("Échec de realloc");
                        goto start;
                    } else
                        d->d = newData;
                }
                d->len = len;
                d->seq = (d->seq + 1) & 65535;;
                memcpy(d->d, received, len);
                updated_our_data = 0;
                updated_our_network = 0;
                printf("Notre nouveau num de seq %d\n", d->seq);
                printf("Notre nouveau message : %s\n", d->d);
            }
            if (FD_ISSET(s, &fdreads)) {
                struct sockaddr_in6 sender;
                socklen_t addr_len = sizeof(struct sockaddr_in6);
                memset(received, 0, 1024);
                size_t len_received = recvfrom(s, received, 1024, 0, &sender,
                                               &addr_len);
                if (len_received < 0) {
                    perror("Échec de recvfrom");
                    goto start;
                }
                char *error = paquet_ok(received, len_received);
                unsigned long error_len = strlen(error);
                if (error_len > 0) {
                    send_warning(&sender, error);
                } else {
                    int i = getneighbour(&sender);
                    if (i == -1) {
                      int neigh = add_neighbour(&sender, 0);
                      if ( neigh == -1 ) {
                          printf("Table des voisins pleine, on ignore un paquet d'envoyeur inconnu");
                          goto start;
                        }
                      printf(" <== Reçu un paquet d'un nouveau voisin ! <==\n");
                    } else {
                  //     printf(" <== Reçu du voisin d'indice %d, un paquet de taille %zu <==\n",
                    //          i, len_received);
                    }
                    time(&neighTable.table[i].last_package);
                    tlv table[16384];
                    memset(table, 0, 4096 * sizeof(tlv));
                    int table_len = 0;
                    unsigned char *current_tlv = received + 4;
                    unsigned char *fin_paquet = received + len_received - 1;
                    while (current_tlv < fin_paquet) {
                        unsigned char type = current_tlv[0];
                        unsigned char tlv_len = current_tlv[1];
                        if (type > 1 && type < 10) {
                            table_len += tlv_processor[type](current_tlv,
                                                             table,
                                                             table_len);
                        }
                        current_tlv = current_tlv + tlv_len + 2;
                    }
                    if (table_len > 0) {
                        quickSort(table, 0, table_len - 1);
                        unsigned int total_sent_bis = 0;
                        unsigned int j = 0;
                        unsigned int total_sent = 0;
                        unsigned int amount_of_packages = 0;
                        time_t timer = time(NULL);
                        while (j < table_len) {
                            size_t weight = 0;
                            unsigned int k = 0;
                            while (((weight + (table[j + k].length + 2)) <
                                    1020) && (j + k < table_len)) {
                                weight += (table[j + k].length + 2);
                                k++;
                            }
                            unsigned char *package = package_builder(
                                    table + j, k);
                            int sent = package_sender(&sender, package);
                            total_sent += sent;
                            total_sent_bis += sent;
                            amount_of_packages += 1;
                            if (total_sent > 128000) {
                                now = time(NULL);
                                double elapsed_time = difftime(now, timer);
                                double advance = 1 - elapsed_time;
                                if (advance > 0) {
                                    usleep((advance *
                                            1000000)); //usleep prend des microsecondes
                                    printf("Débit d'envoi supérieur à 128Ko/s : on attend %f secondes\n",
                                           advance);
                                }
                                total_sent = 0;
                                timer = time(NULL);
                            }
                            j += k;
                        }
                      //  printf(" ==> Envoyé au voisin d'indice %d, en %d paquet(s), %d octets ==>\n",
                       //     i, amount_of_packages, total_sent_bis);
                    }
                }
            }
        }
    }
    return 0;
}
