#include <stdio.h>
#include <string.h>
#include <stdlib.h>

enum states { start, config, option, rule, action, protocol, srcip, srcport, destip, destport, msg, content, sid, end};
typedef enum {false, true} bool;

int main()
{
	char line[1024];
	line[0]='\0';
	char data[1024];
	data[0]='\0';
	//char *output;
	FILE *fd,*fd2;
	fd = fopen("/etc/config/snort_rule", "r");
	fd2 = fopen("/etc/snort/rules/local.rules","w");	
	enum states network;
	network = start;
	
	while ( fgets(line, 1023, fd))
	{
		network = start;
		//printf("%s", line);
		char* cursor;
		cursor = line;
		char buffer[512];
		int i = 0;
		if(line[0]=='\n')
			continue;

		//printf("%s\n",line);
		while ( *cursor != NULL)
		{
			//output= malloc(sizeof(char)*1024);
			/* if ( *cursor != '\t' && *cursor != ' ' && *cursor != '\n' && *cursor != '\r') */
			if ( *cursor > 32 && *cursor !=39)
			{
				/* Accumulate character to word */
				buffer[i] = *cursor;
				i++;
			}
			else
			{
				buffer[i] = '\0';
				if ( i != 0 ) /* printf("Token : %s\n", buffer); */
				{
						/* Finite State Machine Code */
						switch (network)
						{
							case start:
								if ( !strcmp(buffer, "config") ) {
									network = config;
									//initHead(buffer);
								}
								if ( !strcmp(buffer, "option") ) {
									network = option;
									//initHead(buffer);
								}
								//printf("First Token : %s\n", buffer);
								break;
							case config:
								//printf("Config Token : %s\n", buffer);
								network = start;
								break;
							case option:
								//printf("Option Token : %s\n", buffer);
								if(!strcmp(buffer,"action")) {
									network = action;
								}
								else if(!strcmp(buffer,"protocol")) {
									network = protocol;
								}
								else if(!strcmp(buffer,"srcip")) {
									network = srcip;
								}
								else if(!strcmp(buffer,"srcport")) {
									network = srcport;
								}
								else if(!strcmp(buffer,"destip")) {
									network = destip;
								}
								else if(!strcmp(buffer,"destport")) {
									network = destport;
								}
								else if(!strcmp(buffer,"msg")) {
									network = msg;
								}
								else if(!strcmp(buffer,"content")) {
									network = content;
								}
								else if(!strcmp(buffer,"sid")) {
									network = sid;
								}
								break;
							case action:
								//printf("action = %s\n", buffer);
								strcat(data,buffer);
								break;
							case protocol:
								//printf("protocol = %s\n", buffer);
								strcat(data," ");
								strcat(data,buffer);
								break;
							case srcip:
								//printf("srcip = %s\n", buffer);	
								strcat(data," ");
								strcat(data,buffer);
								break;
							case srcport:
								//printf("srcport = %s\n", buffer);
								strcat(data," ");
								strcat(data,buffer);
								break;
							case destip:
								//printf("destip = %s\n", buffer);
								strcat(data," -> ");
								strcat(data,buffer);
								break;
							case destport:
								//printf("destport = %s\n", buffer);
								strcat(data," ");
								strcat(data,buffer);
								break;
							case msg:
								//printf("msg = %s\n", buffer);
								strcat(data," (msg:\"");
								strcat(data,buffer);
								strcat(data,"\";");
								break;
							case content:
								//printf("content = %s\n", buffer);
								strcat(data," content:\"");
								strcat(data,buffer);
								strcat(data,"\";");
								break;
							case sid:
								//printf("sid = %s\n", buffer);
								strcat(data," sid:");
								strcat(data,buffer);
								strcat(data,";)");
								//printf("rule = %s\n",data);
								fprintf(fd2,"%s\n",data);
								data[0]='\0';
								break;
							default:
								printf("Null Line\n");
						}
						
						/* End of Finite State Machine Code */
				}
				i=0; /* Add Token */
			}
			cursor++;
			//free(output);
		}
		
		
		
	}
	printf("snort local rule file completed!!\n");
	fclose(fd);
	fclose(fd2);
	return 0;
}
