# usbtables makefile supporting Prolog
# Jan 1, 2016
# root@davejingtian.org
# http://davejingtian.org

CC	= gcc
GPLC	= gplc
LIBS	=
INCS	=
SRC	= usbfilter.pl usbtables.c nlm.c utils.c logic.c
TGT	= usbtables

all: $(TGT)

usbtables: $(SRC)
	$(GPLC) $(SRC) --c-compiler $(CC) -C $(INCS) -L $(LIBS) -o $(TGT)

clean:
	rm -rf $(TGT)
