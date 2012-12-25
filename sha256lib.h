#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/* Define o tamanho do buffer a ser usado na leitura de um ficheiro*/
#define BUFFER_FICHEIRO 10000

/* Constantes iniciais usadas no calculo do hash */
#define H0         0x6a09e667
#define H1         0xbb67ae85
#define H2         0x3c6ef372
#define H3         0xa54ff53a
#define H4         0x510e527f
#define H5         0x9b05688c
#define H6         0x1f83d9ab
#define H7         0x5be0cd19

/* Funcoes usadas no algoritmo */
#define Ch(x,y,z)	((x & y) ^ (~x & z))
#define Maj(x,y,z)	((x & y) ^ (x & z) ^ (y & z))
#define Rotr(x,y)	((x >> y) | (x << (32 - y)))
#define e0(x)		(Rotr(x,2) ^ Rotr(x,13) ^ Rotr(x,22))
#define e1(x)		(Rotr(x,6) ^ Rotr(x,11) ^ Rotr(x,25))
#define s0(x)		(Rotr(x,7) ^ Rotr(x,18) ^ (x >> 3))
#define s1(x)		(Rotr(x,17) ^ Rotr(x,19) ^ (x >> 10))

/* Estrutura usada para manter o estado */
struct SHA256_St {
	unsigned int hash[8];
	unsigned char data[64];
	unsigned int total_len;
	unsigned int offset;
};

/* Função de inicialização da estrutura SHA256_St */
void init_SHA256(struct SHA256_St *context);

/* Função usada para o cálculo sucessivo de blocos de dados */
void update_SHA256(struct SHA256_St *context,
     unsigned char *buf, unsigned len);

/* Função que termina os cálculos (se necessário) e devolve o
 * resumo */
void final_SHA256(struct SHA256_St *context,
     unsigned char hash[32]);

/* Função recebe o nome do ficheiro e devolve o resumo.
 * Em caso de erro (e.g., não conseguiu abrir o ficheiro)
 * deve devolver –1. */
int file_SHA256(char *file_name, unsigned char hash[32]);

/*
 * Get the elapsed time in microseconds.
 *
 * Usage:
 * 1) declare two timeval structures   - struct timeval begin, end;
 * 2) To get the time at the beginning - getTime(begin);
 * 3) To get the time at the end       - getTime(end);
 * 4) To print the results    - printTime(stdout, "", begin, end);
 */
#define getTime(BEGIN) gettimeofday(&(BEGIN), (struct timezone*) 0)
#define elapTime(BEGIN, END)                               \
     (1e+6*((END).tv_sec - (BEGIN).tv_sec) +               \
     ((END).tv_usec - (BEGIN).tv_usec))
#define printTime(FILE, MESG, BEGIN, END)                  \
        fprintf(FILE, "Elapsed time(usec) %s :%.2f\n",     \
            MESG, elapTime(BEGIN, END))
