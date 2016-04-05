# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.4

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CMake.app/Contents/bin/cmake

# The command to remove a file.
RM = /Applications/CMake.app/Contents/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/cwood/Projects/dissect

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/cwood/Projects/dissect

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/Applications/CMake.app/Contents/bin/ccmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/Applications/CMake.app/Contents/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/cwood/Projects/dissect/CMakeFiles /Users/cwood/Projects/dissect/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/cwood/Projects/dissect/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named dissect

# Build rule for target.
dissect: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 dissect
.PHONY : dissect

# fast build rule for target.
dissect/fast:
	$(MAKE) -f CMakeFiles/dissect.dir/build.make CMakeFiles/dissect.dir/build
.PHONY : dissect/fast

#=============================================================================
# Target rules for targets named libdissect

# Build rule for target.
libdissect: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 libdissect
.PHONY : libdissect

# fast build rule for target.
libdissect/fast:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/build
.PHONY : libdissect/fast

#=============================================================================
# Target rules for targets named test_packet

# Build rule for target.
test_packet: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 test_packet
.PHONY : test_packet

# fast build rule for target.
test_packet/fast:
	$(MAKE) -f CMakeFiles/test_packet.dir/build.make CMakeFiles/test_packet.dir/build
.PHONY : test_packet/fast

src/buffer.o: src/buffer.c.o

.PHONY : src/buffer.o

# target to build an object file
src/buffer.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/buffer.c.o
.PHONY : src/buffer.c.o

src/buffer.i: src/buffer.c.i

.PHONY : src/buffer.i

# target to preprocess a source file
src/buffer.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/buffer.c.i
.PHONY : src/buffer.c.i

src/buffer.s: src/buffer.c.s

.PHONY : src/buffer.s

# target to generate assembly for a file
src/buffer.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/buffer.c.s
.PHONY : src/buffer.c.s

src/dissect.o: src/dissect.c.o

.PHONY : src/dissect.o

# target to build an object file
src/dissect.c.o:
	$(MAKE) -f CMakeFiles/dissect.dir/build.make CMakeFiles/dissect.dir/src/dissect.c.o
.PHONY : src/dissect.c.o

src/dissect.i: src/dissect.c.i

.PHONY : src/dissect.i

# target to preprocess a source file
src/dissect.c.i:
	$(MAKE) -f CMakeFiles/dissect.dir/build.make CMakeFiles/dissect.dir/src/dissect.c.i
.PHONY : src/dissect.c.i

src/dissect.s: src/dissect.c.s

.PHONY : src/dissect.s

# target to generate assembly for a file
src/dissect.c.s:
	$(MAKE) -f CMakeFiles/dissect.dir/build.make CMakeFiles/dissect.dir/src/dissect.c.s
.PHONY : src/dissect.c.s

src/packet.o: src/packet.c.o

.PHONY : src/packet.o

# target to build an object file
src/packet.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/packet.c.o
.PHONY : src/packet.c.o

src/packet.i: src/packet.c.i

.PHONY : src/packet.i

# target to preprocess a source file
src/packet.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/packet.c.i
.PHONY : src/packet.c.i

src/packet.s: src/packet.c.s

.PHONY : src/packet.s

# target to generate assembly for a file
src/packet.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/packet.c.s
.PHONY : src/packet.c.s

src/test/test_packet.o: src/test/test_packet.c.o

.PHONY : src/test/test_packet.o

# target to build an object file
src/test/test_packet.c.o:
	$(MAKE) -f CMakeFiles/test_packet.dir/build.make CMakeFiles/test_packet.dir/src/test/test_packet.c.o
.PHONY : src/test/test_packet.c.o

src/test/test_packet.i: src/test/test_packet.c.i

.PHONY : src/test/test_packet.i

# target to preprocess a source file
src/test/test_packet.c.i:
	$(MAKE) -f CMakeFiles/test_packet.dir/build.make CMakeFiles/test_packet.dir/src/test/test_packet.c.i
.PHONY : src/test/test_packet.c.i

src/test/test_packet.s: src/test/test_packet.c.s

.PHONY : src/test/test_packet.s

# target to generate assembly for a file
src/test/test_packet.c.s:
	$(MAKE) -f CMakeFiles/test_packet.dir/build.make CMakeFiles/test_packet.dir/src/test/test_packet.c.s
.PHONY : src/test/test_packet.c.s

src/tlv.o: src/tlv.c.o

.PHONY : src/tlv.o

# target to build an object file
src/tlv.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/tlv.c.o
.PHONY : src/tlv.c.o

src/tlv.i: src/tlv.c.i

.PHONY : src/tlv.i

# target to preprocess a source file
src/tlv.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/tlv.c.i
.PHONY : src/tlv.c.i

src/tlv.s: src/tlv.c.s

.PHONY : src/tlv.s

# target to generate assembly for a file
src/tlv.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/tlv.c.s
.PHONY : src/tlv.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... dissect"
	@echo "... test_packet"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... libdissect"
	@echo "... src/buffer.o"
	@echo "... src/buffer.i"
	@echo "... src/buffer.s"
	@echo "... src/dissect.o"
	@echo "... src/dissect.i"
	@echo "... src/dissect.s"
	@echo "... src/packet.o"
	@echo "... src/packet.i"
	@echo "... src/packet.s"
	@echo "... src/test/test_packet.o"
	@echo "... src/test/test_packet.i"
	@echo "... src/test/test_packet.s"
	@echo "... src/tlv.o"
	@echo "... src/tlv.i"
	@echo "... src/tlv.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

