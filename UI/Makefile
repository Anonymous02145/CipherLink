CXX = clang++
CXXFLAGS = -std=c++17 -Wall -O2
DEBUGFLAGS = -g -DDEBUG
LIBS = -lglfw -ldl -lGL

SRC_DIR = src
OUTPUT_DIR = output

CPP_FILES := $(shell find $(SRC_DIR) -name "*.cpp")
OUTPUTS := $(patsubst $(SRC_DIR)/%.cpp,$(OUTPUT_DIR)/%,$(CPP_FILES))

# Force X11 for compilation/runtime
export GDK_BACKEND := x11

all: $(OUTPUT_DIR) $(OUTPUTS)

$(OUTPUT_DIR)/%: $(SRC_DIR)/%.cpp src/glad.c
	@mkdir -p $(dir $@)
	@echo "Compiling $< ..."
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

debug: CXXFLAGS += $(DEBUGFLAGS)
debug: clean all

clean:
	rm -rf $(OUTPUT_DIR)

.PHONY: all debug clean
