BASEDIR         = ./
OPENSSLINCLUDES = $(HOME)/DEV/ciscossl-1.1.1c.7.1.3/BUILD/include
OPENSSLLIBS     = $(HOME)/DEV/ciscossl-1.1.1c.7.1.3/BUILD/lib

TARGET          = openssl_client

CXX             = g++

CXXFLAGS        = -O0 -g -Wall -std=c++11 -lm

CXXFLAGS       += -I$(BASEDIR) \
									-I$(OPENSSLINCLUDES)

LDFLAGS         = -L$(OPENSSLLIBS)

LDLIBS          = -lssl -lcrypto

.SUFFIXES: .cpp

.cpp.o:
	  $(CXX) $(CXXFLAGS) -c $<

.cpp:
	  $(CXX) $(CXXFLAGS) $< -o $@ -lg++

SRC = main.cpp \
			TLS13_Crypto.cpp

OBJS = $(addsuffix .o, $(basename $(SRC)))

all:  $(TARGET)

$(TARGET):  $(OBJS)
	  $(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	  rm -f $(OBJS)
		rm -f $(TARGET)
