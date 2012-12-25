#include "sha256lib.h"

int main()
{
	FILE *file;
	struct timeval begin, end;
	int i;
	struct SHA256_St ctx;
	unsigned char hash[32];

/*********BUFFERS DE TESTE************/
	int nVezes = 100;
	double res1 = 0;
	double res10 = 0;
	double res100 = 0;
	double res1000 = 0;
	double res10000 = 0;
	double res100000 = 0;
	double res1000000 = 0;
	unsigned char bufA[1] = "a";
	unsigned char bufDezA[10];
	unsigned char bufCemA[100];
	unsigned char bufMilA[1000];
	unsigned char bufDezMilA[10000];
	unsigned char bufCemMilA[100000];
	unsigned char bufMilhaoA[1000000];

/**********TESTES*************/

/**PREENCHIMENTO DOS BUFFERS******/

	for(i=0;i<10;i++){
		bufDezA[i] = 'a';
	}
	for(i=0;i<100;i++){
		bufCemA[i] = 'a';
	}
	for(i=0;i<1000;i++){
		bufMilA[i] = 'a';
	}
	for(i=0;i<10000;i++){
		bufDezMilA[i] = 'a';
	}		
	for(i=0;i<100000;i++){
		bufCemMilA[i] = 'a';
	}
	for(i=0;i<1000000;i++){
		bufMilhaoA[i] = 'a';
	}

/*****BATERIA DE TESTES PARA BUFFERS**/

	for(i = 0; i < nVezes; i++){
		getTime(begin);
		init_SHA256(&ctx);
		update_SHA256(&ctx,bufA,1);
		final_SHA256(&ctx,hash);
		getTime(end);
		res1 += elapTime(begin,end);
//		printf("res: %.2f\n",res);
//		printTime(stdout, "", begin, end);

		getTime(begin);
		init_SHA256(&ctx);
		update_SHA256(&ctx,bufDezA,10);
		final_SHA256(&ctx,hash);
		getTime(end);
		res10 += elapTime(begin,end);
//		printf("res: %.2f\n",res);
//		printTime(stdout, "", begin, end);

		getTime(begin);
		init_SHA256(&ctx);
		update_SHA256(&ctx,bufCemA,100);
		final_SHA256(&ctx,hash);
		getTime(end);
		res100 += elapTime(begin,end);
//		printf("res: %.2f\n",res);
//		printTime(stdout, "", begin, end);

		getTime(begin);
		init_SHA256(&ctx);
		update_SHA256(&ctx,bufMilA,1000);
		final_SHA256(&ctx,hash);
		getTime(end);
		res1000 += elapTime(begin,end);
//		printf("res: %.2f\n",res);
//		printTime(stdout, "", begin, end);

		getTime(begin);
		init_SHA256(&ctx);
		update_SHA256(&ctx,bufDezMilA,10000);
		final_SHA256(&ctx,hash);
		getTime(end);
		res10000 += elapTime(begin,end);
//		printf("res: %.2f\n",res);
//		printTime(stdout, "", begin, end);

		getTime(begin);
		init_SHA256(&ctx);
		update_SHA256(&ctx,bufCemMilA,100000);
		final_SHA256(&ctx,hash);
		getTime(end);
		res100000 += elapTime(begin,end);
//		printf("res: %.2f\n",res);
//		printTime(stdout, "", begin, end);

		getTime(begin);
		init_SHA256(&ctx);
		update_SHA256(&ctx,bufMilhaoA,1000000);
		final_SHA256(&ctx,hash);
		getTime(end);
		res1000000 += elapTime(begin,end);
//		printf("res: %.2f\n",res);
//		printTime(stdout, "", begin, end);
	}
	res1 /= nVezes;
	res10 /= nVezes;
	res100 /= nVezes;
	res1000 /= nVezes;
	res10000 /= nVezes;
	res100000 /= nVezes;
	res1000000 /= nVezes;
	printf("res1: %.2f\n", res1);
	printf("res10: %.2f\n", res10);
	printf("res100: %.2f\n", res100);
	printf("res1000: %.2f\n", res1000);
	printf("res10000: %.2f\n", res10000);
	printf("res100000: %.2f\n", res100000);
	printf("res1000000: %.2f\n", res1000000);

/**********CRIAÇÃO DOS FICHEIROS DE TESTE************/


/*
	file = fopen("a.txt","w");
	for(i=0;i<1;i++){
		fprintf(file,"%c",'a');	
	}
	fclose(file);
	file = fopen("DezA.txt","w");
	for(i=0;i<10;i++){
		fprintf(file,"%c",'a');	
	}
	fclose(file);
	file = fopen("CemA.txt","w");
	for(i=0;i<100;i++){
		fprintf(file,"%c",'a');	
	}
	fclose(file);
	file = fopen("MilA.txt","w");
	for(i=0;i<1000;i++){
		fprintf(file,"%c",'a');	
	}
	fclose(file);
	file = fopen("10KA.txt","w");
	for(i=0;i<10000;i++){
		fprintf(file,"%c",'a');	
	}
	fclose(file);
	file = fopen("100KA.txt","w");
	for(i=0;i<100000;i++){
		fprintf(file,"%c",'a');	
	}
	fclose(file);
	file = fopen("MA.txt","w");
	for(i=0;i<1000000;i++){
		fprintf(file,"%c",'a');	
	}
	fclose(file);

*/


/***********BATERIA DE TESTES PARA FICHEIROS***************/
	res1 = 0;
	res10 = 0;
	res100 = 0;
	res1000 = 0;
	res10000 = 0;
	res100000 = 0;
	res1000000 = 0;

	for(i = 0; i < nVezes; i++){

		getTime(begin);
		file_SHA256("a.txt", hash);
		getTime(end);
		res1 += elapTime(begin,end);

		getTime(begin);
		file_SHA256("DezA.txt", hash);
		getTime(end);
		res10 += elapTime(begin,end);

		getTime(begin);
		file_SHA256("CemA.txt", hash);
		getTime(end);
		res100 += elapTime(begin,end);

		getTime(begin);
		file_SHA256("MilA.txt", hash);
		getTime(end);
		res1000 += elapTime(begin,end);
	
		getTime(begin);
		file_SHA256("10KA.txt", hash);
		getTime(end);
		res10000 += elapTime(begin,end);

		getTime(begin);
		file_SHA256("100KA.txt", hash);
		getTime(end);
		res100000 += elapTime(begin,end);

		getTime(begin);
		file_SHA256("MA.txt", hash);
		getTime(end);
		res1000000 += elapTime(begin,end);
	}
	res1 /= nVezes;
	res10 /= nVezes;
	res100 /= nVezes;
	res1000 /= nVezes;
	res10000 /= nVezes;
	res100000 /= nVezes;
	res1000000 /= nVezes;
	printf("res1: %.2f\n", res1);
	printf("res10: %.2f\n", res10);
	printf("res100: %.2f\n", res100);
	printf("res1000: %.2f\n", res1000);
	printf("res10000: %.2f\n", res10000);
	printf("res100000: %.2f\n", res100000);
	printf("res1000000: %.2f\n", res1000000);

/*******************************************************/

	for(i = 0;i < 32; i++){
		printf("%x ",hash[i]);
	}
	printf("\n");

	return (0);
}
