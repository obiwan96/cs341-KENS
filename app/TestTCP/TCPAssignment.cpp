/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
  if(domain!=AF_INET||type!=SOCK_STREAM){
    returnSystemCall(syscallUUID, -1);
    return;
  }
  int fd=createFileDescriptor(pid);
  sock_list.push_back(std::make_tuple(std::make_tuple(pid,fd),std::make_tuple(NULL,NULL)));
  returnSystemCall(syscallUUID,fd);
}
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket)
{
  int size=sock_list.size();
  for(int i = 0; i < size; i++){
    if(std::get<1>(std::get<0>(sock_list[i]))==socket){
      sock_list.erase(sock_list.begin()+i+1);
      removeFileDescriptor(pid,socket);
      returnSystemCall(syscallUUID,0);
      return;
    }
  }
  returnSystemCall(syscallUUID,-1);
}
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len)
{
  tuple_sockets sock=std::make_tuple(pid, socket);
  tuple_binds bin;
  const struct sockaddr_in *addr_in=(const struct sockaddr_in *)address;
  uint32_t ip_addr=ntohl(addr_in->sin_addr.s_addr);
  uint16_t port=ntohs(addr_in->sin_port);
  for(int i = 0; i<sock_list.size();i++){
    bin=std::get<1>(sock_list[i]);
    if(std::get<1>(bin)==port){
      if(std::get<0>(bin)==INADDR_ANY||std::get<0>(bin)==ip_addr||ip_addr==INADDR_ANY){//bind rule
        returnSystemCall(syscallUUID,-1);
        return;
      }
    }
  }
  bin=std::make_tuple(ip_addr,port);
  for(int i = 0; i<sock_list.size();i++){
    if(std::get<0>(sock_list[i])==sock){
      if(std::get<1>(sock_list[i])!=std::make_tuple(NULL,NULL)){//already binded socket
//          std::cout << std::get<0>(std::get<1>(sock_list[i])) <<" " <<  std::get<1>(std::get<1>(sock_list[i])) << "\n";
          returnSystemCall(syscallUUID,-1);
          return;
      }
      sock_list[i]=std::make_tuple(sock,bin);
      returnSystemCall(syscallUUID,0);
      return;
    }
  }
  returnSystemCall(syscallUUID,-1);
}
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len){
  struct sockaddr_in *addr_in = (struct sockaddr_in*)address;
  memset(addr_in, 0, sizeof(struct sockaddr_in));
  tuple_sockets sock=std::make_tuple(pid,socket);
  tuple_binds bin;
  for(int i = 0; i<sock_list.size();i++){
    if(std::get<0>(sock_list[i])==sock){
      bin=std::get<1>(sock_list[i]);
      if(bin==std::make_tuple(NULL,NULL)){//not binded socket
        returnSystemCall(syscallUUID,-1);
        return;
      }
      addr_in->sin_family=AF_INET;
      addr_in->sin_addr.s_addr=htonl(std::get<0>(bin));
      addr_in->sin_port=htons(std::get<1>(bin));
      returnSystemCall(syscallUUID,0);
      return;
    }
  }
  returnSystemCall(syscallUUID,-1);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int socket,const struct sockaddr *address,socklen_t address_len);

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
   this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int,param.param3_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
//		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t>(param.param3_int));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
