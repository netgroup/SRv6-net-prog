#ifndef SRHOOK_H_
#define SRHOOK_H_

int bind_sid_north(const char *sid, const int set_operation, const char *vnf_eth, const unsigned char *mac);
int bind_nic_south(const char *vnf_eth, const int set_operation, const char *sid);

int unbind_sid_north(const char *sid);
int unbind_nic_south(const char *vnf_eth);

int show_north(char *dst, size_t size);
int show_south(char *dst, size_t size);

#endif /* SRHOOK_H_ */

