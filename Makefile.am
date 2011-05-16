# Copyright (C) 2003 David J. Lambert

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA.


guilemoduledir = $(datadir)/guile/net

lib_LTLIBRARIES = libguile-pcap.la

DOT_X_FILES = guile-pcap.x

BUILT_SOURCES = $(DOT_X_FILES)

libguile_pcap_la_SOURCES = guile-pcap.c

libguile_pcap_la_LIBADD = $(PCAP_LIBS)

libguile_pcap_la_LDFLAGS = -export-dynamic

SUFFIXES = .x

.c.x:
	$(GUILE_SNARF) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) $< > $@ \
	|| { rm $@; false; }

install-data-local:
	mkdir -p -m755 $(guilemoduledir)
	$(INSTALL_DATA) pcap.scm $(guilemoduledir)/pcap.scm
	$(INSTALL_DATA) pcap.txt $(guilemoduledir)/pcap.txt

EXTRA_DIST = pcap.scm 
EXTRA_DIST += guile-pcap.texi

#EXTRA_DIST += pcap.txt procedures-manual.texi

#info_TEXINFOS = guile-pcap.texi


# if MAINTAINER_MODE

# ### Guile documentation snarfing 

# # Relies on tools supplied with, but not installed by, Guile.  For
# # maintainers only.

# SUFFIXES += .doc

# dotdoc2texi       = cat $(DOT_DOC_FILES) | $(snarf2checkedtexi)
# snarf2checkedtexi = guile-tools snarf-check-and-output-texi

# DOT_DOC_FILES = guile-pcap.doc

# BUILT_SOURCES += $(DOT_DOC_FILES) pcap.txt \
# 		procedures-manual.texi procedures-online.texi \
# 		guile-pcap.info

# guile-pcap.texi: procedures-manual.texi

# # .c.doc: %.c
# # 	(guile-snarf-docs  $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) $< | \
# # 	guile_filter_doc_snarfage --filter-snarfage) > $@ || { rm $@; false; }

# procedures-manual.texi: $(DOT_DOC_FILES)
# 	$(dotdoc2texi) | grep -v "^" > $@ || { rm $@; false; }

# procedures-online.texi: $(DOT_DOC_FILES)
# 	$(dotdoc2texi) > $@ || { rm $@; false; }

# pcap.txt: procedures-online.texi
# 	rm -f $@
# 	makeinfo --force -o $@ $< || test -f $@

# endif


CLEANFILES = $(BUILT_SOURCES)
