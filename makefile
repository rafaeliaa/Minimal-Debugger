CC = gcc
CFLAGS = -Wall -Wextra -g -O0
LIBS = -lelf -lcapstone

TARGET = mdb
SRC = mdb.c
TEST = test
TESTSRC = test.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

test: $(TESTSRC)
	$(CC) -g -O0 -no-pie -o $(TEST) $(TESTSRC)

run: $(TARGET)
	./$(TARGET) $(TEST)

clean:
	rm -f $(TARGET) $(TEST)