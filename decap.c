#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

uint32_t read32()
{
	
	uint32_t b0 = 0;
	uint32_t b1 = 0;
	uint32_t b2 = 0;
	uint32_t b3 = 0;
	
	fscanf(stdin,"%02x",&b0);
	//printf("Byte0 is %02x\n",b0);
	fscanf(stdin,"%02x",&b1);
	//printf("Byte1 is %02x\n",b1);
	fscanf(stdin,"%02x",&b2);
	//printf("Byte2 is %02x\n",b2);
	fscanf(stdin,"%02x",&b3);
	//printf("Byte3 is %02x\n",b3);
	
	return (((b3 << 24) & 0xFF000000) + ((b2 << 16) & 0x00FF0000) + ((b1 << 8) & 0x0000FF00) + (b0 & 0x000000FF));
	
}

void skip(uint32_t length)
{
	for(uint16_t i=0;i<length;i++)
	{
		fscanf(stdin,"%*02x",NULL);
	}
}

void readframe(uint32_t *frame, uint32_t length)
{
	for(uint16_t i=0;i<length;i++)
	{
		fscanf(stdin,"%02x",&frame[i]);
	}
}

void eth2_ex(uint32_t *frame,uint32_t *mac,uint16_t *ethertype,uint16_t *eth2_hl)
{
   mac[0] = (((frame[0] << 16) & 0x00FF0000) + ((frame[1] << 8) & 0x0000FF00) +((frame[2]) & 0x000000FF)) & 0x00FFFFFF;
   mac[1] = (((frame[3] << 16) & 0x00FF0000) + ((frame[4] << 8) & 0x0000FF00) +((frame[5]) & 0x000000FF)) & 0x00FFFFFF;
   mac[2]= (((frame[6] << 16) & 0x00FF0000) + ((frame[7] << 8) & 0x0000FF00) +((frame[8]) & 0x000000FF)) & 0x00FFFFFF;
   mac[3] = (((frame[9] << 16) & 0x00FF0000) + ((frame[10] << 8) & 0x0000FF00) +((frame[11]) & 0x000000FF)) & 0x00FFFFFF;
   *ethertype = ((frame[12] << 8) & 0x0000FF00) +((frame[13]) & 0x000000FF);
   *eth2_hl = 6 + 6 + 2;
	  
}

uint8_t ipv4_ex(uint32_t *frame,uint32_t blkcl,uint16_t eth2_hl,uint32_t *ipv4_ip,uint8_t *ipv4_protocol,uint16_t *ipv4_hl,uint16_t *ipv4_id, uint16_t *ipv4_pl)
{
   uint16_t total_l = ((frame[eth2_hl+2] << 8) & 0xFF00) + ((frame[eth2_hl+3]) & 0x00FF);
   if(((frame[eth2_hl+0] >> 4) & 0x0F) == 4)
   {
	  *ipv4_hl=(frame[eth2_hl+0] & 0x0F)*4;
	  *ipv4_pl=total_l-*ipv4_hl;
	  *ipv4_id = ((frame[eth2_hl+4] << 8) & 0xFF00) + ((frame[eth2_hl+5]) & 0x00FF);
	  *ipv4_protocol = frame[eth2_hl+9];
	  
	  for(int i=0; i<8;i++)
	  {
		 ipv4_ip[i] = frame[eth2_hl+12+i];
	  }
	  return 0;
   }
   else
   {
	  //printf("IPv4 Corrupted\n");
	  return 1;
   }
   
}

void ipv6_ex()
{
   //Might be implemented later for know ignore IPv6
}

uint8_t udp_ex(uint32_t *frame,uint32_t blkcl,uint16_t eth2_hl,uint16_t ipv4_hl, uint16_t ipv4_pl,uint16_t *udp_port,uint16_t *udp_pl)
{
   uint16_t offset = eth2_hl + ipv4_hl;
   uint16_t total_l = ((frame[offset+4] << 8) & 0xFF00) + ((frame[offset+5]) & 0x00FF);
   if((blkcl-offset-total_l) == 0)
   {
	  udp_port[0] = ((frame[offset+0] << 8) & 0xFF00) + ((frame[offset+1]) & 0x00FF);
	  //printf("Source Port is %d\n",udp_port[0]);
	  udp_port[1] = ((frame[offset+2] << 8) & 0xFF00) + ((frame[offset+3]) & 0x00FF);
	  //printf("Destination Port is %d\n",udp_port[1]);
	  *udp_pl=ipv4_pl-8;
	  //printf("UDP Payload is %d bytes long\n",*udp_pl);
	  return 0;
   }
   else
   {
	  //printf("UDP Corrupted\n");
	  return 1;
   }
}

void tcp_ex(uint32_t *frame,uint32_t blkcl,uint16_t eth2_hl,uint16_t ipv4_hl, uint16_t ipv4_pl, uint16_t *tcp_port, uint16_t *tcp_hl, uint16_t *tcp_pl)
{
   uint16_t offset = eth2_hl + ipv4_hl;
   *tcp_hl = ((frame[offset+12] >> 4) & 0x000F)*4;
   //printf("TCP header length is %d bytes\n",*tcp_hl);
   
   tcp_port[0] = ((frame[offset+0] << 8) & 0xFF00) + ((frame[offset+1]) & 0x00FF);
   //printf("Source Port is %d\n",tcp_port[0]);
   tcp_port[1] = ((frame[offset+2] << 8) & 0xFF00) + ((frame[offset+3]) & 0x00FF);
   //printf("Destination Port is %d\n",tcp_port[1]);
   *tcp_pl = ipv4_pl - *tcp_hl;
   //printf("TCP Payload is %d bytes long\n",*tcp_pl);
}

uint8_t httpget_ex(uint32_t *frame,uint16_t eth2_hl,uint16_t ipv4_hl, uint16_t  tcp_udp_hl, uint16_t tcp_udp_pl)
{
	uint8_t buffer[1000];
	uint32_t http_req_l;
	
	
	uint8_t method[4];
	uint8_t host[7];
	uint16_t offset = eth2_hl + ipv4_hl + tcp_udp_hl;
	
	uint8_t probe;
	uint32_t cursor;
	uint32_t max_curs= tcp_udp_pl - tcp_udp_hl - 1;
	uint32_t SP_loc[2];
	uint8_t SP_n;
	uint32_t CR_loc;
	//uint32_t LF_loc;
	
	uint8_t *http_URI = NULL;
	uint32_t URI_size;
	uint8_t *http_ver = NULL;
	uint32_t ver_size;
	uint8_t *http_hos = NULL;
	uint32_t hos_size;
	uint32_t i;

	
	
	method[0]= ((frame[offset+0]) & 0xFF);
	method[1]= ((frame[offset+1]) & 0xFF); 
	method[2]= ((frame[offset+2]) & 0xFF);
	method[3]= 0x00;
	//printf("%s\n",method);
	if((method[0] == 'G') && (method[1] == 'E') && (method[2] == 'T'))
	{
		//printf("Get detected\n");
		cursor=0;
		probe=0;
		SP_n=0;
		do
		{
			probe=((frame[offset+cursor]) & 0xFF);
			if((probe==0x20) && (SP_n<2)){SP_loc[SP_n]=cursor;SP_n++;}
			if(probe==0x0D){CR_loc=cursor;}
			//if(probe==0x0A){LF_loc=cursor;}
			
			cursor++;
			if(cursor>max_curs){return 2;}
		
		}while(probe != 0x0A);
		
		URI_size = (SP_loc[1]-SP_loc[0]);
		if(URI_size != 0)
		{
			http_URI = (uint8_t*) malloc(URI_size * sizeof(uint8_t));
			if(http_URI == NULL)                     
			{
				printf("Error, malloc failed\n");
				return 2;
			}
			i=0;
			for(cursor=(SP_loc[0]+1);cursor<(SP_loc[1]);cursor++)
			{
				http_URI[i]=((frame[offset+cursor]) & 0xFF);
				i++;
			}
			http_URI[i]=0x00;
		}
		
		
		ver_size = (CR_loc-SP_loc[1]);
		if(ver_size != 0)
		{
			http_ver = (uint8_t*) malloc(ver_size * sizeof(uint8_t));
			if(http_ver == NULL)                     
			{
				printf("Error, malloc failed\n");
				if(http_URI != NULL){free(http_URI);}
				return 2;
			}
			i=0;
			for(cursor=(SP_loc[1]+1);cursor<(CR_loc);cursor++)
			{
				http_ver[i]=((frame[offset+cursor]) & 0xFF);
				i++;
			}
			http_ver[i]=0x00;
		}
		
		if(cursor+8<max_curs)
		{
			cursor=cursor+2;
			//printf("%d\n",cursor);
			for(i=0;i<6;i++)
			{
				host[i]=((frame[offset+cursor]) & 0xFF);
				cursor++; 
			}
			
			if((host[0]==0x48) && (host[1]==0x6F) && (host[2]==0x73) && (host[3]==0x74) && (host[4]==0x3A) && (host[5]==0x20))
			{
				//printf("Host found");
				SP_loc[0]=cursor-1;
				do
				{
					probe=((frame[offset+cursor]) & 0xFF);
					if(probe==0x0D){CR_loc=cursor;}
					//if(probe==0x0A){LF_loc=cursor;}
			
					cursor++;
					if(cursor>max_curs){return 2;}
		
				}while(probe != 0x0A);
				
				hos_size = (CR_loc-SP_loc[0]);
				if(hos_size != 0)
				{
					http_hos = (uint8_t*) malloc(hos_size * sizeof(uint8_t));
					if(http_hos == NULL)                     
					{
						printf("Error, malloc failed\n");
						if(http_URI != NULL){free(http_URI);}
						if(http_ver != NULL){free(http_ver);}
						return 2;
					}
					i=0;
					for(cursor=(SP_loc[0]+1);cursor<(CR_loc);cursor++)
					{
						http_hos[i]=((frame[offset+cursor]) & 0xFF);
						i++;
					}
					http_hos[i]=0x00;
				}
			}
				
		}
		
		
		
		
		//if((http_URI != NULL) && (http_ver != NULL) && (http_hos != NULL)){printf("GET  %s %s %s\n",http_hos,http_URI,http_ver);}
		
		if((http_URI != NULL) && (http_hos != NULL)){printf("%s,%s",http_hos,http_URI);}
		
		
		if(http_URI != NULL){free(http_URI);}
		if(http_ver != NULL){free(http_ver);}
		if(http_hos != NULL){free(http_hos);}
		
		return 0;
	}
	else
	{
		return 1;
	}
	

}


int main (void)
{
//-------------VARIABLES------------------------------------------------------

	//---------PCAPNG Block-----------
	uint32_t blkty; //Type
	uint32_t blkle; //Total Length of Block
	uint32_t blkid; //Interface ID
	uint32_t blkth; //Timestamp High
	uint32_t blktl; //Timestamp Low
	uint32_t blkcl; //Captured Length of Frame
	uint32_t blkol; //Original Length 0f Frame
	uint8_t blkpd; //Frame padding
	uint32_t blkop; //Options Length
	uint32_t *frame; //Memory Pointer to Frame Store
   	
	//---------Ethernet II------------
	uint32_t eth2_mac[4];
	//eth2_mac[0] is Source Vendor MAC
	//eth2_mac[1] is Source Unique MAC
	//eth2_mac[2] is Dest. Vendor MAC
	//eth2_mac[3] is Dest. Unique MAC
	uint16_t eth2_protocol; //Ethertype ==> 0x0800 IPv4 ; 0x86DD IPv6
	uint16_t eth2_hl; //Eth.II Header Length
   
	//---------IPv4-------------------
	uint32_t ipv4_ip[8];
	//ipv4_ip[0] to ipv4_ip[3] is Source IP
	//ipv4_ip[4] to ipv4_ip[7] is Dest. IP
	uint16_t ipv4_id; //Packet ID used to recognise where fragments belong
	uint8_t ipv4_protocol; //Protocol
	uint16_t ipv4_hl; //IPv4 Header Length
	uint16_t ipv4_pl; //IPv4 Payload Length
   
	//---------IPv6-------------------
	//Might be implemented later for know ignore IPv6
   
	//---------UDP--------------------
	uint16_t udp_port[2];
	//udp_port[0] is the source port
	//udp_port[1] is the destination port
	uint8_t udp_hl = 8; //UDP Header Length
	uint16_t udp_pl; //UDP Payload Length
 
	//---------TCP--------------------
	uint16_t tcp_port[2];
	//tcp_port[0] is the source port
	//tcp_port[1] is the destination port
	uint16_t tcp_hl; //TCP Header Length
	uint16_t tcp_pl; //TCP Payload Length
	
	//---------EC---------------------
	uint8_t E_ipv4;
	uint8_t E_udp;
//-------------VARIABLES------------------------------------------------------


	uint32_t framenum = 0;
	do
	{
		blkty = read32();
		blkle = read32();
		
		
		if(blkty == 0x00000006) //If Enhanced Packet Block
		{
			blkid = read32();
			blkth = read32();
			blktl = read32();
			blkcl = read32();
			blkol = read32();
			
			//printf("--------------------------\n");
			//printf("Block Type: %08x\n",blkty);
			//printf("Block Length: %08x\n",blkle);
			//printf("Interface ID: %08x\n",blkid);
			//printf("Timestamp (High): %08x\n",blkth);
			//printf("Timestamp (Low): %08x\n",blktl);
			//printf("Captured Packet Length: %08x\n",blkcl);
			//printf("Original Packet Length: %08x\n",blkol);
			
			//--------------Check if all frame is present--------------
			if(blkcl==blkol) 
			{
				frame = (uint32_t*) malloc(blkcl * sizeof(uint32_t));
				if(frame == NULL)                     
				{
					printf("Error, malloc failed\n");
					exit(0);
				}
				readframe(frame,blkcl);
				//--------------Process Frame---------------------------
				
				eth2_ex(frame,eth2_mac,&eth2_protocol,&eth2_hl);
				if(eth2_protocol == 0x0800)
				{
					E_ipv4 = ipv4_ex(frame,blkcl,eth2_hl,ipv4_ip,&ipv4_protocol,&ipv4_hl,&ipv4_id,&ipv4_pl);
				
					if(ipv4_protocol == 1 && E_ipv4 == 0)
					{
						printf("%d,%08x,%08x,%06X,%06X,%06X,%06X,IPv4,%d.%d.%d.%d,%d.%d.%d.%d,%d,ICMP,0,0,0,0,0,0\n",framenum+1,blkth,blktl,eth2_mac[0],eth2_mac[1],eth2_mac[2],eth2_mac[3],ipv4_ip[0],ipv4_ip[1],ipv4_ip[2],ipv4_ip[3],ipv4_ip[4],ipv4_ip[5],ipv4_ip[6],ipv4_ip[7],ipv4_id);
					}
				
					if(ipv4_protocol == 6 && E_ipv4 == 0)
					{
						tcp_ex(frame,blkcl,eth2_hl,ipv4_hl,ipv4_pl,tcp_port,&tcp_hl,&tcp_pl);
						printf("%d,%08x,%08x,%06X,%06X,%06X,%06X,IPv4,%d.%d.%d.%d,%d.%d.%d.%d,%d,TCP,%d,%d,%d,",framenum+1,blkth,blktl,eth2_mac[0],eth2_mac[1],eth2_mac[2],eth2_mac[3],ipv4_ip[0],ipv4_ip[1],ipv4_ip[2],ipv4_ip[3],ipv4_ip[4],ipv4_ip[5],ipv4_ip[6],ipv4_ip[7],ipv4_id,tcp_port[0],tcp_port[1],tcp_pl);
						if((tcp_port[1] == 80) && (tcp_pl !=  0))
						{
							if(httpget_ex(frame,eth2_hl,ipv4_hl,tcp_hl,tcp_pl) == 0)
							{
								printf(",0\n");
							}
							else
							{
								printf("0,0,0\n");
							}
						}
						else
						{
							printf("0,0,0\n");
						}
					}
					if(ipv4_protocol == 17 && E_ipv4 == 0)
					{
						E_udp = udp_ex(frame,blkcl,eth2_hl,ipv4_hl,ipv4_pl,udp_port,&udp_pl);
						if(E_udp ==0)
						{
							printf("%d,%08x,%08x,%06X,%06X,%06X,%06X,IPv4,%d.%d.%d.%d,%d.%d.%d.%d,%d,UDP,%d,%d,%d,",framenum+1,blkth,blktl,eth2_mac[0],eth2_mac[1],eth2_mac[2],eth2_mac[3],ipv4_ip[0],ipv4_ip[1],ipv4_ip[2],ipv4_ip[3],ipv4_ip[4],ipv4_ip[5],ipv4_ip[6],ipv4_ip[7],ipv4_id,udp_port[0],udp_port[1],udp_pl);
							if((udp_port[1] == 80) && (udp_pl !=  0))
							{
								if(httpget_ex(frame,eth2_hl,ipv4_hl,udp_hl,udp_pl) == 0 )
								{
									printf(",0\n");
								}
								else
								{
									printf("0,0,0\n");
								}
							}
							else
							{
								printf("0,0,0\n");
							}	
						}
					}
					//--------------Process Frame---------------------------
					free(frame);
				}
				else
				{
					//printf("Frame is not Ethernet II skipping\n");
				}
			}
			else
			{
				//printf("Frame %d: Error Truncated\n",framenum);
			}
			//--------------Check if all frame is present--------------
			//--------------Find Padding and Options Size--------------
			if((blkcl%4)==0)
		 	{
				blkpd = 0;
		 	}
			else
			{
				blkpd = 4-(blkcl%4);
			}
			blkop = blkle - 28 - 4 - blkcl - blkpd;
			//--------------Find Padding and Options Size--------------
			
			skip(blkpd+blkop+4); //Skip Padding + Options + Total Length (2)

			
			framenum++;//Increment Framenum	
		}
		else // If not Enhanced Packet Block
		{
			skip(blkle-8); //Skip Whole Block
		}
		
	}while(1);	
	
  	return EXIT_SUCCESS;
}
