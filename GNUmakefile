#
# 'make depend' uses makedepend to automatically generate dependencies 
#               (dependencies are added to end of Makefile)
# 'make'        build executable file 'masker'
# 'make clean'  removes all .o and executable files
#

# Define directories
SRCDIR = ./src
INCDIR = ./include
BINDIR = ./bin
OBJDIR = ./obj
LIBDIR = ./lib

# Define the C compiler to use
CXX = /usr/bin/clang++

# Define any compile-time flags - C++
#CXXFLAGS = -std=c++0x -Wall -g -O2 -fPIC
CXXFLAGS = -std=c++11 -Wall -g -O2 -fPIC

# define any directories containing header files other than /usr/include
#
INCLUDES = -I$(INCDIR) -I/usr/local/include

# define library paths in addition to /usr/lib
#   if I wanted to include libraries not in /usr/lib I'd specify
#   their path using -Lpath, something like:
LFLAGS = -L$(LIBDIR) -L/usr/local/lib

# define any libraries to link into executable:
#   if I want to link in libraries (libx.so or libx.a) I use the -llibname 
#   option, something like (this will link in libmylib.so and libm.so:
LIBS = -lm -lcryptopp

# Define the C++ source files
SRCS = $(wildcard $(SRCDIR)/*.cpp)

# Define the C++ object files 
#
# This uses Suffix Replacement within a macro:
#   $(name:string1=string2)
#         For each word in 'name' replace 'string1' with 'string2'
# Below we are replacing the suffix .cpp of all words in the macro SRCS
# with the .o suffix.
#
# $(notdir <files list with dir>) removes the directory portion in the
# list of files.
#
# $(addprefix <prefix>,<files list>) adds prefix to the list of files.
#
OBJS = $(addprefix $(OBJDIR)/,$(notdir $(SRCS:.cpp=.o)))

# Define the executable file 
MAIN = $(BINDIR)/masker

#
# The following part of the makefile is generic; it can be used to 
# build any executable just by changing the definitions above and by
# deleting dependencies appended to the file from 'make depend'
#

.PHONY: depend clean

all:    $(MAIN)
	@echo The binary has been compiled
	@echo ----------

$(MAIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

# This is a suffix replacement rule for building .o's from .cpp's
# it uses automatic variables $<: the name of the prerequisite of
# the rule(a .c file) and $@: the name of the target of the rule (a .o file) 
# (see the gnu make manual section about automatic variables)
$(OBJDIR)/%.o:$(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) $(OBJS) $(INCDIR)/*~ $(SRCDIR)/*~ *~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) -Y $^

# DO NOT DELETE THIS LINE -- make depend needs it

