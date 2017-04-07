#ifndef SRHELPER_H_
#define SRHELPER_H_


#ifndef NS_IN6ADDRSZ
	#define NS_IN6ADDRSZ sizeof(struct in6_addr)
#endif

#ifndef NS_INT16SZ
	#define NS_INT16SZ (long unsigned int) 2 
#endif

#ifdef SPRINTF_CHAR
# define SPRINTF(x) strlen(sprintf/**/x)
#else
# define SPRINTF(x) ((size_t)sprintf x)
#endif



const char *
inet_ntop4(const u_char *src, char *dst, size_t size);

const char *
inet_ntop6(const u_char *src, char *dst, size_t size);



#endif /* SRHELPER_H_ */

