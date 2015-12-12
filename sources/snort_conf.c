#include <stdio.h>
#include <string.h>
#include <stdlib.h>

enum states { start, config, option, list ,type, key, name, value, end};
typedef enum {false, true} bool;
char line[1024];
typedef struct _node{
	char token[1024];
	struct _node* next;
}node;

node* head;
void initHead(char *title)
{	
	strcpy(head->token,title);
};
void putNode(char *tail)
{
	node* new;
	node* temp;
	new = (node*)malloc(sizeof(node));
	if(*tail==39)
		printf("hi\n");
		
	//printf("new !! %s",new->token);
	strcpy(new->token,tail);
	new->next=NULL;
	//printf("new !! %s",new->token);
	for(temp=head;temp->next;temp=temp->next)
	{
			//printf("%s ",target->token);
	}

	//
	temp->next=new;

	/*new->next=head->next;
	head->next=new;*/
};
bool delNode()
{
	node* del;
	del = head->next;
	if(del==NULL)
		return false;
	
	head->next = del->next;
	free(del);
	return true;
};

int main()
{
	line[1023]='\0';
	node* target;
	//char *output;
	FILE *fd,*fd2;
	fd = fopen("/etc/config/snort", "r");
	fd2 = fopen("/tmp/snort.conf","w");
	
	head = (node*)malloc(sizeof(node));
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
								if(!strcmp(buffer,"list")) {
									network = list;
								}
								//printf("First Token : %s\n", buffer);
								break;
							case config:
								//printf("Config Token : %s\n", buffer);
								network = type;
								//putNode(buffer);
								initHead(buffer);
								break;
							case option:
								//printf("Option Token : %s\n", buffer);
								network = key;
								putNode(buffer);
								break;
							case list:
								//printf("List Token : %s\n", buffer);
								network = key;
								break;
							case type:
								//printf("Type value : %s\n", buffer);
								network = start;
								//putNode(buffer);
								//initHead(buffer);
								break;
							case key:
								//printf("Key value : %s\n", buffer);
								if ( *(cursor+1) < 33 ) network = start;
								else network = key;
								
								putNode(buffer);
								
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
		
		if(head->next)
		{
			//printf("\n1.%s ",head->token);
			//printf("\n1.");
			
			
			for(target=head;target;target=target->next)
			{
				fprintf(fd2,"%s ",target->token);
				//printf("%s ",target->token);
			}
			
			fprintf(fd2,"\n");
			//printf("\n");
			//printf("end!\n");
			for(;head->next;)
			{
				//printf("start! ");
				delNode();
			}
			
		}
		
	}
	printf("snort configure file completed!!\n");
	free(head);
	fclose(fd);
	fclose(fd2);
	return 0;
}
