# The UUID of the extension.
extension_uuid := mitm-me@foudil.fr

# The name of the profile dir where the extension can be installed.
profile_dir := mitm-me-dev

# The zip application to be used.
ZIP := zip

# The target location of the build and build files.
build_dir := ../build

# The target XPI file.
xpi_name := $(extension_uuid).xpi
xpi_file := $(build_dir)/$(xpi_name)

# The type of operating system this make command is running on.
# os_type := $(patsubst darwin%,darwin,$(shell echo $(OSTYPE)))
# we don't want to: export OSTYPE; make install
os_type := $(patsubst darwin%,darwin,$(shell echo $$OSTYPE))

# The location of the extension profile.
ifeq ($(os_type), darwin)
  profile_location := \
    ~/Library/Application\ Support/Firefox/Profiles/$(profile_dir)/extensions
else
  ifeq ($(os_type), linux-gnu)
    profile_location := \
      ~/.mozilla/firefox/$(profile_dir)/extensions
  else
    profile_location := \
      "$(subst \,\\,$(APPDATA))\\Mozilla\\Firefox\\Profiles\\$(profile_dir)\\extensions"
  endif
endif

# The install.rdf file.
install_rdf := install.rdf

# The chrome.manifest file.
chrome_manifest := chrome.manifest

# The preferences dir.
preferences_dir := defaults/preferences

# The root of the JAR sources.
chrome_source_root := chrome

# The sources for the JAR file.
chrome_sources := $(wildcard $(chrome_source_root)/content/*.js) \
               $(wildcard $(chrome_source_root)/content/*.xul) \
               $(wildcard $(chrome_source_root)/content/*.xml) \
               $(wildcard $(chrome_source_root)/content/*.css) \
               $(wildcard $(chrome_source_root)/skin/*.css) \
               $(wildcard $(chrome_source_root)/skin/*.png) \
               $(wildcard $(chrome_source_root)/locale/*/*.dtd) \
               $(wildcard $(chrome_source_root)/locale/*/*.properties)

# The sources for the XPI file. Uses variables defined in the included
# Makefiles.
xpi_includes := $(install_rdf) \
             $(chrome_manifest) \
             $(preferences_dir)/prefs.js \
             $(chrome_sources)

$(xpi_file): $(build_dir) $(xpi_includes)
	@echo "Creating XPI file."
	@$(ZIP) $(xpi_file) $(xpi_includes)
	@echo "Creating XPI file. Done!"

# This builds the extension XPI file.
.PHONY: all
all: $(xpi_file)
	@echo
	@echo "Build finished successfully."
	@echo

# This cleans all temporary files and directories created by 'make'.
.PHONY: clean
clean: clean_build clean_profile
	@echo "Cleanup is done."

# This builds everything except for the actual XPI, and then it copies it to the
# specified profile directory, allowing a quick update that requires no install.
.PHONY: install
install: $(xpi_file) $(profile_location)
	@echo "Installing in profile folder: $(profile_location)"
	@cp -f $(xpi_file) $(profile_location)
	@echo "Installing in profile folder. Done!"
	@echo

$(build_dir):
	@if [ ! -x $(build_dir) ]; \
  then \
    mkdir -p $(build_dir); \
  fi

$(profile_location):
	@echo "Creating extension folder: $(profile_location)"
	@if [ ! -x $(profile_location) ]; \
  then \
    mkdir -p $(profile_location); \
  fi

clean_build:
	@echo "Removing build dir: $(build_dir)"
	@rm -rf $(build_dir)

clean_profile:
	@echo "Removing extension from extension folder: $(profile_location)"
	@rm -f $(profile_location)/$(xpi_name)
