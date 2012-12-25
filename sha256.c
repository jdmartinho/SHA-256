#include "sha256lib.h"

/* Constantes usadas nos 64 rounds do SHA-256 */
unsigned int K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Função de inicialização da estrutura SHA256_St */
void init_SHA256(struct SHA256_St *context){
	context->hash[0] = H0;
	context->hash[1] = H1;
	context->hash[2] = H2;
	context->hash[3] = H3;
	context->hash[4] = H4;
	context->hash[5] = H5;
	context->hash[6] = H6;
	context->hash[7] = H7;
	memset(context->data, 0, sizeof(context->data));
	context->total_len = 0;	
	context->offset = 0;
}

/* Função auxiliar que processa um bloco de dados */

void processa_bloco(struct SHA256_St *context){
	unsigned int W[64];
	unsigned int a, b, c, d, e, f, g, h;
	unsigned int t1, t2;
	int t;

	/*passo1*/

	for(t = 0; t < 16; ++t)
	{
		W[t] = (((unsigned int)(context->data[t * 4 + 0])) << 24) |
		       (((unsigned int)(context->data[t * 4 + 1])) << 16) |
		       (((unsigned int)(context->data[t * 4 + 2])) <<  8) |
		        ((unsigned int)(context->data[t * 4 + 3]));		
	}
	for(t = 16; t < 64; ++t)
	{
		W[t] = (s1(W[t - 2]) + W[t - 7] + s0(W[t - 15]) + W[t - 16]);
	}

	/*passo2*/
	
	a = context->hash[0];
	b = context->hash[1];
	c = context->hash[2];
	d = context->hash[3];
	e = context->hash[4];
	f = context->hash[5];
	g = context->hash[6];
	h = context->hash[7];

	/*passo3*/

	for(t = 0; t < 64; ++t){
		t1 = h + e1(e) + Ch(e,f,g) + K[t] + W[t];
		t2 = e0(a) + Maj(a,b,c);
		h=g;
		g=f;
		f=e;
		e=d+t1;
		d=c;
		c=b;
		b=a;
		a=t1+t2;	
	}

	/*passo4*/

	context->hash[0] += a;
	context->hash[1] += b;
	context->hash[2] += c;
	context->hash[3] += d;
	context->hash[4] += e;
	context->hash[5] += f;
	context->hash[6] += g;
	context->hash[7] += h;
}

/* Função usada para o cálculo sucessivo de blocos de dados */
void update_SHA256(struct SHA256_St *context, unsigned char *buf, unsigned len){
	//actualizar o tamanho total em bytes
	context->total_len += len;
	int cont = len;
	int tamanho;
	//enquanto houver bytes no buf
	while(cont > 0){
		//guarda o tamanho dos bytes que já entraram
		tamanho = context->offset + cont;

		//se for necessário mais do que um bloco
		if(tamanho >= 64){
			memcpy(&context->data[context->offset], &buf[len-cont], (64-(context->offset)));
			processa_bloco(context);
			cont = cont - (64-(context->offset));
			context->offset = 0;			
			tamanho = 0;
		}
		//se o bloco for menor que 64 bytes (512 bits)
		else{
			memcpy(&context->data[context->offset], &buf[len-cont], cont);
			context->offset += cont;			
			cont = 0;
		}		 
	}
}

/* Função que termina os cálculos (se necessário) e devolve o resumo */
void final_SHA256(struct SHA256_St *context, unsigned char hash[32]){
	unsigned long long totalBits;		
	int i = 56;
	int j = 0;
	//se existir espaço no último bloco para colocar o tamanho
	if(context->offset < 56){
		//coloca o 1
		context->data[context->offset] = (unsigned char) 128;
		context->offset++;
	}
	//caso contrário vai ser necessário um novo bloco
	else{
		//coloca o 1
		context->data[context->offset] = (unsigned char) 128;
		context->offset++;
		while(context->offset < 64){
			//coloca os zeros
			context->data[context->offset] = (unsigned char) 0;
			context->offset++;
		}
		processa_bloco(context);
		context->offset = 0;		
	}
	//coloca zeros até aos últimos 8 bytes que serão para o tamanho	
	while(context->offset < 56){ 
		context->data[context->offset] = (unsigned char) 0;
		context->offset++;
	}
	
	//tamanho da mensagem em bits
	totalBits = context->total_len << 3;

	//copiar o tamanho em bits para o último bloco a ser processado
	for(; i >= 0; i = i-8){
		context->data[context->offset] = totalBits >> i;		
		context->offset++;
	}

	processa_bloco(context);

	//copiar a hash final da estrutura para o array dado
	i = 0;
	for(; j<8; j++){
		hash[i++] = context->hash[j] >> 24;
		hash[i++] = context->hash[j] >> 16;
		hash[i++] = context->hash[j] >> 8;
		hash[i++] = context->hash[j];
	}
}

/* Função recebe o nome do ficheiro e devolve o resumo.
 * Em caso de erro (e.g., não conseguiu abrir o ficheiro)
 * deve devolver -1. */
int file_SHA256(char *file_name, unsigned char hash[32]){
	FILE *ficheiro;
	unsigned char C;
	int cont = 0;
	unsigned char buf[BUFFER_FICHEIRO];
	struct SHA256_St ctx;	
	
	//abre o ficheiro, devolve -1 se não conseguir
	if ((ficheiro = fopen(file_name, "rb")) == NULL){        	
		return -1;
	}
		  
	//inicializa a estrutura
	init_SHA256(&ctx);
	
	//le o ficheiro byte a byte
	while((fread(&C,1,1,ficheiro)) > 0){
		buf[cont] = C;
		cont++;	
		if(cont == BUFFER_FICHEIRO){
			update_SHA256(&ctx,buf,cont);
			cont=0;
		}
	}
	//processa o último (ou único) bloco
	update_SHA256(&ctx,buf,cont);
	//finaliza o algoritmo
	final_SHA256(&ctx,hash);
	fclose(ficheiro);
	return 0;
}
