CXX		= g++
CFLAGS  = -02 -std=c++11 -Wno-attributes

Test_App_Name 			?= jalapeno_test 
Test_App_Cpp_Files 		:= $(Test_App_Name).cpp
Jalapeno_Lib_Path 		:= ../lib

Test_App_Objects 		:= $(Test_App_Cpp_Files:.cpp=.o)
# Test_App_Include_Flags	:= -I/home/trippel/jalapeno/lib/App -I/opt/intel/sgxsdk/include
# Test_App_Link_Flags 	:= -L$(Jalapeno_Lib_Path)

all: $(Test_App_Name)

%.o: %.cpp
	$(CXX) $(CFLAGS) -c -o $@ $< /home/trippel/jalapeno/lib/libjalapeno.so.1.0 -Wl,-rpath=/home/trippel/jalapeno/lib -I/home/trippel/jalapeno/lib/App -I/opt/intel/sgxsdk/include

$(Test_App_Name).exe: $(Test_App_Objects)
	$(CXX) $(CFLAGS) $^ -o $@ $< 

.PHONY: clean

clean:
	rm -f *.o *.exe

# g++ -o jalapeno_test jalapeno_test.cpp -L/home/trippel/jalapeno/lib -ljalapeno -Wl,-rpath=/home/trippel/jalapeno/lib -I/home/trippel/jalapeno/lib/App -I/opt/intel/sgxsdk/include
# g++ -o jalapeno_test jalapeno_test.cpp /home/trippel/jalapeno/lib/libjalapeno.so.1.0 -Wl,-rpath=/home/trippel/jalapeno/lib 
 