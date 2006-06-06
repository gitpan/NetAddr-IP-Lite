/*	inet_aton.c
 *
 * Copyright 2006, Michael Robinton <michael@bizsystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef LOCAL_HAVE_inet_aton
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
                       
int
my_inet_aton(const char *cp, struct in_addr *inp)
{
# ifdef LOCAL_HAVE_inet_pton
  return inet_pton(AF_INET,cp,inp);
# else
#  ifdef LOCAL_HAVE_inet_addr
  inp->s_addr = inet_addr(cp);
  if (inp->s_addr == -1) {
    if (strncmp("255.255.255.255",cp,15) == 0)
      return 1;
    else
      return 0;
  }
  return 1;
#  else
# error inet_aton, inet_pton, inet_addr not defined on this platform
#  endif
# endif
}
#define inet_aton my_inet_aton
#endif
