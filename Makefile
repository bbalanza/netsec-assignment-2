.PHONY: all compile link clean

SOURCE_NAME := attack
COMPILER_FLAGS := -Wall -Wextra -pedantic -Wshadow 
LIBRARIES := -lnet -lpcap
DEBUG := -g

all: ${SOURCE_NAME}.c compile link clean

compile: 
	@echo "Compiling..."
	@gcc -c ${SOURCE_NAME}.c ${COMPILER_FLAGS} ${DEBUG} -o ${SOURCE_NAME}.o

link:   
	@echo "Linking..."
	@gcc ${SOURCE_NAME}.o ${DEBUG} -o ${SOURCE_NAME} ${LIBRARIES}
	@chmod 755 ${SOURCE_NAME}

clean:
	@echo "Cleaning temporary files..."
	@rm ${SOURCE_NAME}.o
