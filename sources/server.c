#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <json/json.h>
#include <fcntl.h>
#define FIFO_FILE "/tmp/fifo"
#define FW_FIFO_FILE "/tmp/fw_fifo"
#define MAX_LINE 1024
#define PORT_NO 9999
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

void jsonparser(char *);  // json parsing function
void input_stream(int);   // system setting input stream
void fw_inoty(void);      // monitoring the fw log in /mnt/log/fw
void inoty(void);         // monitoring the snort log in /mnt/log/snort
void check_fw_fifo(int*); // check the fw_inoty function by fifo stream
void check_fifo(int*);    // check the inoty function by fifo stream
void fw_output_stream(int); // output the fw log in /mnt/log/fw/fw_log to UTM
void output_stream(int);    // output the snort log in /mnt/log/snort/alert to UTM 

int main(int argc, char *argv[])
{
    int listenfd, connfd, connfd2;
	int port_no;
    socklen_t len;
    struct sockaddr_in servaddr, cliaddr;
    pid_t pid;
	pthread_t thread,thread1,thread2;
	
	pid = fork();
	
	if(pid < 0) {
		perror("fork error!");
		exit(1);
	}
	else if(pid == 0) {
		printf("child!\n");
		if((pid = fork())>0) {
			return 0;
		}
		else if(pid == 0) {
			while(1) {
			printf("grand child!!\n");
			if(pthread_create(&thread,NULL,(void*)fw_inoty,NULL)!=0)
				{
					perror("pthread_create error");
					exit(1);
				}
				inoty();
				pthread_join(thread,NULL);
			}
			return 0;
		}
	}
	else {
		printf("parent!\n");
		listenfd = socket(AF_INET, SOCK_STREAM,0);
		if(listenfd <0)
		{
			perror("sock creation error");
			exit(1);
		}
		port_no = atoi(argv[1]);
		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		if(argc !=2)
			servaddr.sin_port = htons(PORT_NO);
		else
			servaddr.sin_port = htons(port_no);

		if(bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr))<0)
		{
			perror("bind error");
			exit(1);
		}
		listen(listenfd,5);	
		printf("TCP thread server run...\n");
        len = sizeof(cliaddr);
        
        while(1) {
			if(mkfifo(FIFO_FILE, 0666) == -1) {
				perror("mkfifo error\n");
			//exit(1);
			}
			if(mkfifo(FW_FIFO_FILE, 0666) == -1) {
				perror("mkfifo error\n");
				//exit(1);
			}
			printf("connecting...\n");
			connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&len);
			connfd2 = accept(listenfd,(struct sockaddr *)&cliaddr,&len);
			printf("Client connected\n");
					
			if(pthread_create(&thread,NULL,(void*)input_stream,(void*)connfd)!=0)
			{
				perror("pthread_create error");
				exit(1);
			}
			if(pthread_create(&thread1,NULL,(void*)fw_output_stream,(void*)connfd2)!=0)
			{
				perror("pthread_create error");
				exit(1);
			}
			output_stream(connfd2);
			close(connfd);
			close(connfd2);
			pthread_join(thread,NULL);
			pthread_join(thread1,NULL);
			printf("connection closed!!\n");
		}
        waitpid(pid,NULL,0);
        //return 0;
	}
    return 0;
}

void jsonparser(char* buff)
{
	int type;
	char raw[1024];
	FILE* fd;

    json_object *myobj, *dataobj;

    myobj = json_tokener_parse(buff);
    
    dataobj = json_object_object_get(myobj, "type");
    type = json_object_get_int(dataobj);
    printf("type = %d\n",json_object_get_int(dataobj));
    dataobj = json_object_object_get(myobj, "raw");
    raw[0]='\0';
    strcpy(raw,json_object_get_string(dataobj));
    printf("raw = %s\n",json_object_get_string(dataobj));
    
    switch(type)
    {
		case 2:
			printf("system command!!\n");
			system(raw);
			break;
		case 3:
			printf("snort setting!!\n");
			system(raw);
			system("uci commit snort");
			break;
		case 4:
			printf("snort rule setting!!\n");
			system(raw);
			system("uci commit snort_rule");
			break;
		case 5:
			 printf("firewall setting!!\n");
			 //printf("%s\n",raw);
			 system(raw);
			 system("uci commit firewall");
			 break;
		case 6:
			printf("error msg!!\n");
			/*
			 * error handling 
			 */
			break;
	}
}
void input_stream(int sockfd)
{
	printf("in!\n");
	int i;
	char line[MAX_LINE];
	
	for(;;)
	{
		line[0]='\0';
		if(read(sockfd,line,MAX_LINE)==0) {
			perror("input read error!!");
			return;
		}
		printf("received!! : ");;
		printf("%s",line);
		jsonparser(line);
		//delay!!
		write(sockfd,"ok",strlen("ok"));	
	}
	printf("terminated!\n");
}
void fw_inoty(void)
{
	int fifo;
	
	int length, i = 0;
	char line[256];
	int fd1;
	int wd;
	char buffer[BUF_LEN];
	char *fifo_data = "fw_fifo data input!!\n";
	
	
	fd1 = inotify_init();
	
	if ( fd1 < 0 ) {
		perror( "inotify_init" );
	}

	wd = inotify_add_watch( fd1, "/mnt/log/fw", 
                          IN_CLOSE_WRITE );
                    
    if((fifo = open(FW_FIFO_FILE, O_WRONLY)) == -1) {
		perror("fifo open error \n");
		return;
		//exit(1);
	}
	
	/*read(fifo, fifo_data, MAX_LINE);
    printf("%s\n",fifo_data);*/
                         
    while(1)
	{
		printf("before read!!\n");
		length = read( fd1, buffer, BUF_LEN );  
		
		printf("read!!\n");
		if ( length < 0 ) {
			perror( "read" );
			printf("error!\n");
		}  

		//while ( i < length ) {
			struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
			printf("Hi!!\n");
			if ( event->len ) {
			  if ( event->mask & IN_CLOSE_WRITE )
			  {
				printf("fw_inoty!!!!!\n");
				if(write(fifo,fifo_data,strlen(fifo_data))) {
					perror("fw inoty fifo error!!");
					return;
				}
			  }
			}
			i += EVENT_SIZE + event->len;
		//}
		i=0;
	}
	printf("event close!\n");
	close(fifo);
	( void ) inotify_rm_watch( fd1, wd );
	( void ) close( fd1 );
}
void inoty(void)
{
	int fifo;
	
	int length, i = 0;
	char line[256];
	int fd1;
	int wd;
	char buffer[BUF_LEN];
	char *fifo_data = "fifo data input!!\n";
	
	
	fd1 = inotify_init();
	
	if ( fd1 < 0 ) {
		perror( "inotify_init" );
	}
  
	wd = inotify_add_watch( fd1, "/mnt/log/snort", 
                          IN_CLOSE_WRITE );
               
    //sleep(10);          
    if((fifo = open(FIFO_FILE, O_WRONLY)) == -1) {
		perror("fifo open error \n");
		return;
		//exit(1);
	}
	
    /*read(fifo, fifo_data, MAX_LINE);
    printf("%s\n",fifo_data);  */
                      
    while(1)
	{
		printf("before read!!\n");
		length = read( fd1, buffer, BUF_LEN );  
		
		printf("read!!\n");
		if ( length < 0 ) {
			perror( "read" );
			printf("error!\n");
		}  

		//while ( i < length ) {
			struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
			if ( event->len ) {
			  if ( event->mask & IN_CLOSE_WRITE )
			  {
				if(write(fifo,fifo_data,strlen(fifo_data))) {
					perror("inoty fifo error!!");
					return;
				}
			  }
			}
			i += EVENT_SIZE + event->len;
		//}
		i=0;
	}
	close(fifo);
	( void ) inotify_rm_watch( fd1, wd );
	( void ) close( fd1 );
}
void check_fw_fifo(int* flag)
{
	int fifo;
	char fifo_data[MAX_LINE];

	
	if((fifo = open(FW_FIFO_FILE, O_RDWR))==-1) {
		perror("fw_fifo open error\n");
		exit(1);
	}
	while(1) {
		read(fifo, fifo_data, MAX_LINE);
        *flag=1;
	}
	close(fifo);
}
void check_fifo(int* flag)
{
	int fifo;
	char fifo_data[MAX_LINE];

	
	if((fifo = open(FIFO_FILE, O_RDWR))==-1) {
		perror("fifo open error\n");
		exit(1);
	}
	//write(fifo,"fifo start",strlen("fifo start"));
	while(1) {
		read(fifo, fifo_data, MAX_LINE);
        *flag=1;
	}
	close(fifo);
}
void fw_output_stream(int sockfd)
{
	printf("fw out!\n");
	FILE* fd;
	char line[MAX_LINE];
    char data[MAX_LINE];
    pthread_t thread; 
    int fifo_flag = 0;
	int current_cursor=0;
    
	if(pthread_create(&thread,NULL,(void*)check_fw_fifo,&fifo_flag)!=0)
	{
		perror("pthread_create error");
		exit(1);
	}
	
	fd = fopen("/mnt/log/fw/fwlog","r");
	//current_cursor = ftell(fd);
	fseek(fd,0,SEEK_END);
	
	data[0]='\0';
    
    strcpy(data,"{\"type\":6,\"raw\":\"");
    
    for(;;) {
		current_cursor = ftell(fd);
        
        if(fifo_flag==1) {
			fclose(fd);
			printf("fw_file new open!\n");
			fd = fopen("/mnt/log/fw/fwlog","r+");
			fseek(fd,current_cursor,SEEK_SET);
			fifo_flag=0;
		}
		
		line[0]='\0';
		sleep(1);
		
		if(fgets(line,255,fd)) {
			if(strlen(line)==0) {continue;}
			strcat(data,line);
			strcat(data,"\"}");
			
			printf("%s",data);
			int cc;
			if(strlen(data)>19) {
			if((cc=write(sockfd,data,strlen(data)))==-1) {
				perror("fw_output write error!!");
				return;
			}
			if(read(sockfd,data,MAX_LINE)==0) {
				perror("input read error!!");
				return;
			}}
			printf("%d\n",cc);
			data[0]='\0';
			strcpy(data,"{\"type\":6,\"raw\":\"");
		}

	}
	pthread_join(thread,NULL);
	fclose(fd);

}
void output_stream(int sockfd)
{
	printf("out!\n");
	FILE* fd;
	ssize_t n;
	pthread_t thread;
	int i,j;
	int fifo_flag = 0;
	int current_cursor=0;
	char c;
    char line[MAX_LINE];
    char data[MAX_LINE];

	fd = fopen("/mnt/log/snort/alert","r");
	//current_cursor = ftell(fd);
	fseek(fd,0,SEEK_END);
	
	if(pthread_create(&thread,NULL,(void*)check_fifo,&fifo_flag)!=0)
	{
		perror("pthread_create error");
		exit(1);
	}
	
	
    data[0]='\0';
    
    strcpy(data,"{\"type\":1,\"raw\":\"");
    for(;;)
    {
		current_cursor = ftell(fd);
        
        if(fifo_flag==1) {
			fclose(fd);
			printf("file new open!\n");
			fd = fopen("/mnt/log/snort/alert","r+");
			fseek(fd,current_cursor,SEEK_SET);
			fifo_flag=0;
		}
		
        line[0]='\0';
       
        printf("cursor = %d\n",ftell(fd));
		sleep(1);
		//scanf("%d",&i);
		i=1;
		switch(i)
		{
			case 1:
				while(fgets(line,255,fd))
				{
					if(strlen(line)==0) { break;}
					if(line[0]=='\n') {		
						strcat(data,"\"}");
						printf("%s",data);
						printf("%d\n",strlen(data));
						if(strlen(data)>19) {
						if(write(sockfd,data,strlen(data))==-1) {
							perror("output wrtie error!!");
							return;
						}
						if(read(sockfd,data,MAX_LINE)==0) {
							perror("input read error!!");
							return;
						}}					
						data[0]='\0';
						strcpy(data,"{\"type\":1,\"raw\":\"");
						break;
					}
					strcat(data,line);
					line[0]='\0';
				}
				break;
			case 2:
				if((c=fgetc(fd))==EOF) {
					/*fclose(fd);
					fd = fopen("text.txt","a+");*/
					printf("EOF!!\n");
					fseek(fd,1,SEEK_END);
				}
				printf("%c",c);
		}
        //scanf("%s",line);
        //write(sockfd,line,n);
        //line[0]='\0';           
    }
    pthread_join(thread,NULL);
    fclose(fd);
}

