#include<stdio.h> 
#include<string.h> 
#include<stdlib.h>
#include<unistd.h>
#include<stdint.h> //For var types
#include<arpa/inet.h> //For converting host byte order to network byte order
#include<sys/socket.h> //For openning the socket
 
#define TARGET "127.0.0.1" //The address to which data is to be sent
//#define TARGET "192.168.98.207"
#define PORT 5606   //The port on which to send data

void delay()
{
	for(int i=0;i<50000000;i++){}
} 

void ins(uint8_t *export,uint8_t num,uint8_t *buffer,uint8_t offset)
{
	//printf("%d\n",num);
	for(uint8_t i=0;i<num;i++)
	{
		export[offset+i]=buffer[i];
	}
} 

uint32_t trunctos(uint64_t timehl)
{
	uint8_t buffer[21];
	uint32_t time;
	sprintf(buffer,"%llu",timehl);
	buffer[20]='\0';
	buffer[10]=0x20;
	//printf("%s\n",buffer);
	sscanf(buffer,"%ld", &time);
	return time;
}
  
  
void main ()
{
	uint8_t buffer[200];
	uint8_t second[200];
	char * cursor;

	uint8_t field;


	uint32_t framenum;
	
	uint8_t timeh_s[9];
	uint8_t timel_s[9];
	uint32_t timeh;
	uint32_t timel;
	uint64_t timeall;
	uint32_t timeout;
	
	uint8_t src_ven_mac_s[7];
	uint8_t src_uni_mac_s[7];
	uint32_t src_ven_mac;
	uint32_t src_uni_mac;
	
	uint8_t dst_ven_mac_s[7];
	uint8_t dst_uni_mac_s[7];
	uint32_t dst_ven_mac;
	uint32_t dst_uni_mac;
	
	uint8_t ip_ver_s[5];
	uint8_t ip_ver;
	
	uint8_t src_ip_s[16];
	uint8_t src_ip[4];
	
	uint8_t dst_ip_s[16];
	uint8_t dst_ip[4];
	
	uint32_t ip_id;
	
	uint8_t proto_s[5];
	uint32_t proto;
	
	uint32_t src_port;
	uint32_t dst_port;
	uint32_t payload_l;
	uint32_t suspi;
	
	/* THIS IS DEFINED IN INCLUDES, I put it here for reference
	struct sockaddr_in {
   	short            sin_family;   // e.g. AF_INET
    	unsigned short   sin_port;     // e.g. htons(3490)
    	struct in_addr   sin_addr;     // see struct in_addr, below
    	char             sin_zero[8];  // zero this if you want to
	};
   	 */
   	 
   	struct sockaddr_in target_addr; //Create Socket Struct
   	int struct_len = sizeof(target_addr);
   	int udp_sock;
   	 
   	// FLOW HEADER FORMAT total 20 bytes
   	uint8_t version[2] = {0x00,0x09}; //NetFlow export format version number
   	uint8_t count[2] = {0x00,0x02}; //Number of flow sets exported in this packet, both template and data (1-30)
	uint8_t sys_uptime[4] = {0x00,0x00,0x00,0x00}; //Current time in milliseconds since the export device booted.
	uint8_t unix_secs[4] = {0x00,0x00,0x00,0x00}; //Current count of seconds since 0000 UTC 1970.
	uint32_t package_sequence = 0;
	uint8_t source_id[4]={0xAA,0xBB,0xCC,0xDD};//Vendor Specific ID
	
	// TEMPLATE FLOWSET total 60 bytes actually
	uint8_t template_flowset_id[2] = {0x00,0x00}; //The flowset_id is used to distinguish template records from data records.
	uint8_t template_length[2] = {0x00,0x3C}; //Has to be the length in bytes of TEMPLATE FLOWSET
	uint8_t template_id[2] = {0x01,0x54}; //The id given to this template
	uint8_t field_count[2] = {0x00,0x0D}; //Field count
	uint8_t field_type[24] = {0,3,0,4,0,56,0,6,0,57,0,6,0,60,0,1,0,8,0,4,0,12,0,4}; //V9 defined fields
	uint8_t field_length[28] = {0,4,0,1,0,54,0,2,0,7,0,2,0,11,0,2,0,1,0,2,0,39,0,1,0,61,0,1};//bytes in field
	
	// DATA FLOWSET 35byte in data 1 padding total 40 bytes actually 36bits
	uint8_t data_flowset_id[2] = {0x01,0x54};
	uint8_t data_length[2] = {0x00,0x28};  //Has to be the length in bytes of Data FLOWSET

	uint8_t net_framenum[4];
	uint8_t net_src_mac[6];
	uint8_t net_dst_mac[6];
	uint8_t net_ipv[1];
	uint8_t net_src_ip[4];
	uint8_t net_dst_ip[4];
	uint8_t net_protocol[1];
	uint8_t net_ipv4_id[2];
	uint8_t net_src_port[2];
	uint8_t net_dst_port[2];
	uint8_t net_payload_len[2];
	uint8_t net_suspi[1];
	uint8_t net_direction[1];
	

    	
    //Open socket in IPv4, to send datagram over UDP
	//udp_sock is now a file descriptor to refers to the endpoint that was created
    if ( (udp_sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        fprintf(stderr,"Socket opening failed\n");
        exit(1);
    }
    
    memset((char *) &target_addr, 0, struct_len); //clear (0) the memory block assigned to target_addr
    target_addr.sin_family = AF_INET; //Specify that the address is IPv4
    target_addr.sin_port = htons(PORT); //Assign converted (host byte order to network byte order) port 
    if (inet_aton(TARGET, &target_addr.sin_addr) == 0) //Assign converted (host byte order to network byte order) address
    {
    	//Return is 0>Failure,1>Success
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
    
    uint8_t netflow_v9[120];
    
    ins(netflow_v9,2,version,0);
	ins(netflow_v9,2,count,2);
	ins(netflow_v9,4,sys_uptime,4);
	ins(netflow_v9,4,unix_secs,8);
	netflow_v9[12]=((package_sequence >> 24) & 0x000000FF);
	netflow_v9[13]=((package_sequence >> 16) & 0x000000FF);
	netflow_v9[14]=((package_sequence >> 8) & 0x000000FF);
	netflow_v9[15]=((package_sequence >> 0) & 0x000000FF);
	ins(netflow_v9,4,source_id,16);
	
	ins(netflow_v9,2,template_flowset_id,20);
	ins(netflow_v9,2,template_length,22);
	ins(netflow_v9,2,template_id,24);
	ins(netflow_v9,2,field_count,26);
	ins(netflow_v9,24,field_type,28);
	ins(netflow_v9,28,field_length,52);

	ins(netflow_v9,2,data_flowset_id,80);
	ins(netflow_v9,2,data_length,82);

	while(1)
	{
		fgets(buffer,200,stdin);

		//Cleanup input
		field = 1;
		for(uint8_t l=0;l<strlen(buffer)+1;l++)
		{
			if(buffer[l]==0x2C){field++;buffer[l]=0x20;} //replace commas with spaces
			if(buffer[l]==0x2E){buffer[l]=0x20;} //replace dots with spaces
			if((field == 8) || (field == 12) || (field == 16) || (field == 17)) //delete fields 8,12,16,17
			{
				second[l]=0x20; //space
			}
			else
			{
				second[l]=buffer[l]; //else copy the character to the next buffer
			}
		}
		
		//UPDATE IPV4 and Protocol in UDP packet (using data in buffer)
		sscanf(buffer,"%*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s %s",ip_ver_s, proto_s);
		if(strcmp(ip_ver_s,"IPv4") == 0){ip_ver=4;}
		else if(strcmp(ip_ver_s,"IPv6") == 0){ip_ver=6;}
		if(strcmp(proto_s,"UDP") == 0){proto=17;}
		else if(strcmp(proto_s,"TCP") == 0){proto=6;}
		else if(strcmp(proto_s,"ICMP") == 0){proto=1;}

		//UPDATE All fields in UDP packet (using data in second)
		framenum = strtoul(second,&cursor,10);
		timeh = strtoul(cursor,&cursor,16);
		timel = strtoul(cursor,&cursor,16);
		src_ven_mac = strtoul(cursor,&cursor,16);
		src_uni_mac = strtoul(cursor,&cursor,16);
		dst_ven_mac = strtoul(cursor,&cursor,16);
		dst_uni_mac = strtoul(cursor,&cursor,16);
		src_ip[0]  = strtoul(cursor,&cursor,10);
		src_ip[1]  = strtoul(cursor,&cursor,10);
		src_ip[2]  = strtoul(cursor,&cursor,10);
		src_ip[3]  = strtoul(cursor,&cursor,10);
		dst_ip[0]  = strtoul(cursor,&cursor,10);
		dst_ip[1]  = strtoul(cursor,&cursor,10);
		dst_ip[2]  = strtoul(cursor,&cursor,10);
		dst_ip[3]  = strtoul(cursor,&cursor,10);
		ip_id  = strtoul(cursor,&cursor,10);
		src_port = strtoul(cursor,&cursor,10);
		dst_port = strtoul(cursor,&cursor,10);
		payload_l = strtoul(cursor,&cursor,10);
		suspi = strtoul(cursor,&cursor,10);
		
		//Print frame data
		printf("nb:%lu th:%08x tl:%08x svm:%03x sum:%03x dvm:%03x dum:%03x iv:%d si:%d.%d.%d.%d di:%d.%d.%d.%d id:%d pr:%d sp:%d dp:%d pl:%d su:%d\n",framenum, timeh, timel, src_ven_mac, src_uni_mac, dst_ven_mac, dst_uni_mac, ip_ver, src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3], ip_id, proto, src_port, dst_port, payload_l, suspi);
		
	
		//Update UPD packet fields into UDP buffer aka netflow_v9
		
		timeall = timeh;
		timeall = timeall << 32;
		timeall = timeall + timel;
		timeout = trunctos(timeall);
			
		netflow_v9[8]=((timeout >> 24) & 0x000000FF);
		netflow_v9[9]=((timeout >> 16) & 0x000000FF);
		netflow_v9[10]=((timeout >> 8) & 0x000000FF);
		netflow_v9[11]=((timeout >> 0) & 0x000000FF);
	
		netflow_v9[12]=((package_sequence >> 24) & 0x000000FF);
		netflow_v9[13]=((package_sequence >> 16) & 0x000000FF);
		netflow_v9[14]=((package_sequence >> 8) & 0x000000FF);
		netflow_v9[15]=((package_sequence >> 0) & 0x000000FF);
		
		net_framenum[0]= ((framenum >> 24) & 0xFF);
		net_framenum[1]= ((framenum >> 16) & 0xFF);
		net_framenum[2]= ((framenum >> 8) & 0xFF);
		net_framenum[3]= ((framenum >> 0) & 0xFF);
		
		net_src_mac[0] = ((src_ven_mac >> 16) & 0xFF);
		net_src_mac[1] = ((src_ven_mac >> 8) & 0xFF);
		net_src_mac[2] = ((src_ven_mac >> 0) & 0xFF);
		net_src_mac[3] = ((src_uni_mac >> 16) & 0xFF);
		net_src_mac[4] = ((src_uni_mac >> 8) & 0xFF);
		net_src_mac[5] = ((src_uni_mac >> 0) & 0xFF);
		
		net_dst_mac[0] = ((dst_ven_mac >> 16) & 0xFF);
		net_dst_mac[1] = ((dst_ven_mac >> 8) & 0xFF);
		net_dst_mac[2] = ((dst_ven_mac >> 0) & 0xFF);
		net_dst_mac[3] = ((dst_uni_mac >> 16) & 0xFF);
		net_dst_mac[4] = ((dst_uni_mac >> 8) & 0xFF);
		net_dst_mac[5] = ((dst_uni_mac >> 0) & 0xFF);
		
		net_ipv[0] = ((ip_ver) & 0xFF);
		
		net_src_ip[0] =  ((src_ip[0]) & 0xFF);
		net_src_ip[1] =  ((src_ip[1]) & 0xFF);
		net_src_ip[2] =  ((src_ip[2]) & 0xFF);
		net_src_ip[3] =  ((src_ip[3]) & 0xFF);
		
		net_dst_ip[0] =  ((dst_ip[0]) & 0xFF);
		net_dst_ip[1] =  ((dst_ip[1]) & 0xFF);
		net_dst_ip[2] =  ((dst_ip[2]) & 0xFF);
		net_dst_ip[3] =  ((dst_ip[3]) & 0xFF);
		
		net_protocol[0] = ((proto) & 0xFF);
		
		net_ipv4_id[0] = ((ip_id >> 8) & 0xFF);
		net_ipv4_id[1] = ((ip_id) & 0xFF);
		
		net_src_port[0] = ((src_port >> 8) & 0xFF);
		net_src_port[1] = ((src_port) & 0xFF);
		
		net_dst_port[0] = ((dst_port >> 8) & 0xFF);
		net_dst_port[1] = ((dst_port) & 0xFF);
		
		net_payload_len[0] = ((payload_l >> 8) & 0xFF);
		net_payload_len[1] = ((payload_l) & 0xFF);
		
		net_suspi[0] = ((suspi) & 0xFF);
		net_direction[0] = 0x01; 
		
		ins(netflow_v9,4,net_framenum,84);
		ins(netflow_v9,6,net_src_mac,88);
		ins(netflow_v9,6,net_dst_mac,94);
		ins(netflow_v9,1,net_ipv,100);
		ins(netflow_v9,4,net_src_ip,101);
		ins(netflow_v9,4,net_dst_ip,105);
		ins(netflow_v9,1,net_protocol,109);
		ins(netflow_v9,2,net_ipv4_id,110);
		ins(netflow_v9,2,net_src_port,112);
		ins(netflow_v9,2,net_dst_port,114);
		ins(netflow_v9,2,net_payload_len,116);
		ins(netflow_v9,1,net_suspi,118);
		ins(netflow_v9,1,net_direction,119);
	
		//send netflow_v9 packet
        if (sendto(udp_sock, netflow_v9, sizeof(netflow_v9) , 0 , (struct sockaddr *) &target_addr, struct_len) == -1) //sendto(sockfd, buf, len, flags, destaddr, addrlen);
        {
        	//Return 0>Success,-1>Failure
            fprintf(stderr,"Failed to send buffer\n");
        	exit(1);
        }
       
        delay();
        printf("Sent\n");
    
   		package_sequence++;
	
		
	}


}

