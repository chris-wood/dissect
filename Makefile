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
CMAKE_SOURCE_DIR = /Users/cwood/dev/dissect

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/cwood/dev/dissect

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
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/cwood/dev/dissect/CMakeFiles /Users/cwood/dev/dissect/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/cwood/dev/dissect/CMakeFiles 0
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
# Target rules for targets named coveralls

# Build rule for target.
coveralls: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 coveralls
.PHONY : coveralls

# fast build rule for target.
coveralls/fast:
	$(MAKE) -f CMakeFiles/coveralls.dir/build.make CMakeFiles/coveralls.dir/build
.PHONY : coveralls/fast

#=============================================================================
# Target rules for targets named coveralls_generate

# Build rule for target.
coveralls_generate: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 coveralls_generate
.PHONY : coveralls_generate

# fast build rule for target.
coveralls_generate/fast:
	$(MAKE) -f CMakeFiles/coveralls_generate.dir/build.make CMakeFiles/coveralls_generate.dir/build
.PHONY : coveralls_generate/fast

#=============================================================================
# Target rules for targets named coveralls_upload

# Build rule for target.
coveralls_upload: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 coveralls_upload
.PHONY : coveralls_upload

# fast build rule for target.
coveralls_upload/fast:
	$(MAKE) -f CMakeFiles/coveralls_upload.dir/build.make CMakeFiles/coveralls_upload.dir/build
.PHONY : coveralls_upload/fast

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

src/cJSON.o: src/cJSON.c.o

.PHONY : src/cJSON.o

# target to build an object file
src/cJSON.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/cJSON.c.o
.PHONY : src/cJSON.c.o

src/cJSON.i: src/cJSON.c.i

.PHONY : src/cJSON.i

# target to preprocess a source file
src/cJSON.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/cJSON.c.i
.PHONY : src/cJSON.c.i

src/cJSON.s: src/cJSON.c.s

.PHONY : src/cJSON.s

# target to generate assembly for a file
src/cJSON.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/cJSON.c.s
.PHONY : src/cJSON.c.s

src/capture.o: src/capture.c.o

.PHONY : src/capture.o

# target to build an object file
src/capture.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/capture.c.o
.PHONY : src/capture.c.o

src/capture.i: src/capture.c.i

.PHONY : src/capture.i

# target to preprocess a source file
src/capture.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/capture.c.i
.PHONY : src/capture.c.i

src/capture.s: src/capture.c.s

.PHONY : src/capture.s

# target to generate assembly for a file
src/capture.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/capture.c.s
.PHONY : src/capture.c.s

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

src/omap.o: src/omap.c.o

.PHONY : src/omap.o

# target to build an object file
src/omap.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/omap.c.o
.PHONY : src/omap.c.o

src/omap.i: src/omap.c.i

.PHONY : src/omap.i

# target to preprocess a source file
src/omap.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/omap.c.i
.PHONY : src/omap.c.i

src/omap.s: src/omap.c.s

.PHONY : src/omap.s

# target to generate assembly for a file
src/omap.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/omap.c.s
.PHONY : src/omap.c.s

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

src/reporter.o: src/reporter.c.o

.PHONY : src/reporter.o

# target to build an object file
src/reporter.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/reporter.c.o
.PHONY : src/reporter.c.o

src/reporter.i: src/reporter.c.i

.PHONY : src/reporter.i

# target to preprocess a source file
src/reporter.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/reporter.c.i
.PHONY : src/reporter.c.i

src/reporter.s: src/reporter.c.s

.PHONY : src/reporter.s

# target to generate assembly for a file
src/reporter.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/reporter.c.s
.PHONY : src/reporter.c.s

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

src/types.o: src/types.c.o

.PHONY : src/types.o

# target to build an object file
src/types.c.o:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/types.c.o
.PHONY : src/types.c.o

src/types.i: src/types.c.i

.PHONY : src/types.i

# target to preprocess a source file
src/types.c.i:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/types.c.i
.PHONY : src/types.c.i

src/types.s: src/types.c.s

.PHONY : src/types.s

# target to generate assembly for a file
src/types.c.s:
	$(MAKE) -f CMakeFiles/libdissect.dir/build.make CMakeFiles/libdissect.dir/src/types.c.s
.PHONY : src/types.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... dissect"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... coveralls_generate"
	@echo "... coveralls"
	@echo "... coveralls_upload"
	@echo "... libdissect"
	@echo "... src/buffer.o"
	@echo "... src/buffer.i"
	@echo "... src/buffer.s"
	@echo "... src/cJSON.o"
	@echo "... src/cJSON.i"
	@echo "... src/cJSON.s"
	@echo "... src/capture.o"
	@echo "... src/capture.i"
	@echo "... src/capture.s"
	@echo "... src/dissect.o"
	@echo "... src/dissect.i"
	@echo "... src/dissect.s"
	@echo "... src/omap.o"
	@echo "... src/omap.i"
	@echo "... src/omap.s"
	@echo "... src/packet.o"
	@echo "... src/packet.i"
	@echo "... src/packet.s"
	@echo "... src/reporter.o"
	@echo "... src/reporter.i"
	@echo "... src/reporter.s"
	@echo "... src/tlv.o"
	@echo "... src/tlv.i"
	@echo "... src/tlv.s"
	@echo "... src/types.o"
	@echo "... src/types.i"
	@echo "... src/types.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

