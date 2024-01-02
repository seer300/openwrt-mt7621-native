EXEC = i2stest
			
OBJS = i2scmd.o 

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -f core *.o $(EXEC)
