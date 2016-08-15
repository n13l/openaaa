#ifndef __WIN32_AF_LOCAL_SYS_UN_H__
#define __WIN32_AF_LOCAL_SYS_UN_H__
                                                                                
struct sockaddr_un {
	u32 sun_family;
	char sun_path[108];
};

#endif
