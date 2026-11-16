# ==============================================================================
# SPATIAL MINUTIAE-GRAPH INDEXING ENGINE (FORENSIC AFIS)
# Principal Systems Software Engineering Build Configuration
# Compiler: GCC (C11 standard) with -O3 Aggressive Optimization Flags
# ==============================================================================

CC ?= gcc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -pedantic -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS ?= -lm

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN_DIR = bin

SRCS = $(SRC_DIR)/btree.c $(SRC_DIR)/kdtree.c $(SRC_DIR)/graph.c $(SRC_DIR)/engine.c
OBJS = $(BUILD_DIR)/btree.o $(BUILD_DIR)/kdtree.o $(BUILD_DIR)/graph.o $(BUILD_DIR)/engine.o
MAIN_SRC = $(SRC_DIR)/main.c
MAIN_OBJ = $(BUILD_DIR)/main.o

ifeq ($(OS),Windows_NT)
    TARGET = $(BIN_DIR)/engine_cli.exe
    SHARED_LIB = $(BIN_DIR)/libengine.dll
    MKDIR = if not exist "$(subst /,\,$(1))" mkdir "$(subst /,\,$(1))"
    RM = del /Q /F
    RMDIR = rmdir /Q /S
else
    TARGET = $(BIN_DIR)/engine_cli
    SHARED_LIB = $(BIN_DIR)/libengine.so
    MKDIR = mkdir -p $(1)
    RM = rm -f
    RMDIR = rm -rf
endif

.PHONY: all clean test benchmark shared

all: $(TARGET) $(SHARED_LIB)

$(BUILD_DIR):
	@$(call MKDIR, $(BUILD_DIR))

$(BIN_DIR):
	@$(call MKDIR, $(BIN_DIR))

# Object compilation rules
$(BUILD_DIR)/btree.o: $(SRC_DIR)/btree.c $(INC_DIR)/btree.h $(INC_DIR)/engine.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/kdtree.o: $(SRC_DIR)/kdtree.c $(INC_DIR)/kdtree.h $(INC_DIR)/engine.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/graph.o: $(SRC_DIR)/graph.c $(INC_DIR)/graph.h $(INC_DIR)/kdtree.h $(INC_DIR)/engine.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/engine.o: $(SRC_DIR)/engine.c $(INC_DIR)/engine.h $(INC_DIR)/btree.h $(INC_DIR)/kdtree.h $(INC_DIR)/graph.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/main.o: $(MAIN_SRC) $(INC_DIR)/engine.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Executable CLI Target
$(TARGET): $(OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo [BUILD COMPLETE] Generated AFIS Engine Binary: $@

# Shared Dynamic Library Target
$(SHARED_LIB): $(OBJS) | $(BIN_DIR)
	$(CC) -shared $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo [BUILD COMPLETE] Generated AFIS Dynamic Library: $@

shared: $(SHARED_LIB)

test: $(TARGET)
	@echo [TEST] Verifying binary compilation and help output...
	$(TARGET)

clean:
	@echo Cleaning build artifacts...
	-@$(RM) $(BUILD_DIR)/*.o 2>nul || rm -f $(BUILD_DIR)/*.o
	-@$(RM) $(TARGET) $(SHARED_LIB) 2>nul || rm -f $(TARGET) $(SHARED_LIB)
