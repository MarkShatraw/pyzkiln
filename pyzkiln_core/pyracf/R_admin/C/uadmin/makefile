# Makefile variables
BASE=$(PYRACF_HOME)

DEPS=irrpcomp.h r_admin.h uadmin.h

SRCS=uadmin.c uadmin_kv.c uadmin_dump.c
OBJS=uadmin.o uadmin_kv.o uadmin_dump.o

# Platform commands
CC=c89
RM=rm -f
CP=cp

# Global arguments
CARGS=-c -Wc,"LANGLVL(EXTENDED),SSCOMM,XPLINK,LP64,ASCII,GOFF" -g
INCS=-I. -I$(BASE)/R_admin/C -I$(BASE)/common/C

all: start $(OBJS) copy_objs

start:
	@echo "--- Make uadmin function"

$(OBJS): $(SRCS) $(DEPS)
	$(CC) $(CARGS) $(INCS) -o $*.o $*.c

$(DEPS):

# Copy all of the built objects for this function back up to the parent
# directory so they can included in the RACF service archive.
copy_objs: $(OBJS)
	$(CP) *.o ..

clean:
	@echo "--- Clean uadmin function"
	$(RM) *.o
	$(RM) CEE*
