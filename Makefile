CXX ?= c++
CPPFLAGS += -Isrc -Ithird_party/httpdwin -Ithird_party/Zar/include
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
LDLIBS += -lssl -lcrypto -pthread
H = third_party/httpdwin
Z = third_party/Zar
SOURCES = src/main.cpp src/database.cpp src/security.cpp src/peer_client.cpp src/pull.cpp src/trigger.cpp src/cors.cpp $(H)/docsec_http.cpp $(H)/httpresponse.cpp $(H)/httprequest.cpp $(H)/httpheaders.cpp $(H)/cookie.cpp $(Z)/src/zar_header.cpp $(Z)/src/zar_store.cpp $(Z)/src/zar_utils.cpp $(Z)/src/zar_stream.cpp
OBJECTS = $(SOURCES:.cpp=.o)
DocSecWin: $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)
%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@
zar-stream-test: tests/zar_stream_test.cpp $(Z)/src/zar_stream.o $(Z)/src/zar_store.o $(Z)/src/zar_header.o $(Z)/src/zar_utils.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $^ $(LDLIBS)
test: DocSecWin zar-stream-test
	./zar-stream-test
	python3 tests/integration.py ./DocSecWin
	python3 tests/trigger_regression.py ./DocSecWin
regression: DocSecWin zar-stream-test
	python3 tests/run_regression.py --server ./DocSecWin --native-test ./zar-stream-test
clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) DocSecWin zar-stream-test
-include $(OBJECTS:.o=.d)
.PHONY: test regression clean
