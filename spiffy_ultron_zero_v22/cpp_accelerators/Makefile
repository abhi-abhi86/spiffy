# Makefile for Bluetooth Scanner C++

CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -fPIC -pthread
LDFLAGS = -shared

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    TARGET = libbt_scanner.dylib
    LDFLAGS += -dynamiclib
    BT_LIBS =
else ifeq ($(UNAME_S),Linux)
    TARGET = libbt_scanner.so
    BT_LIBS = -lbluetooth
else
    TARGET = libbt_scanner.dll
    BT_LIBS =
endif

SRC = bluetooth_scanner.cpp
OBJ = $(SRC:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ $(BT_LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) *.dylib *.so *.dll

install: $(TARGET)
	cp $(TARGET) .

# Note: On Linux, requires libbluetooth-dev
# Install with: sudo apt-get install libbluetooth-dev
