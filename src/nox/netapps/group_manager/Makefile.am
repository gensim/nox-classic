include ../../../Make.vars 

CONFIGURE_DEPENCIES = $(srcdir)/Makefile.am

EXTRA_DIST = \
	meta.json

pkglib_LTLIBRARIES =		\
	group_manager.la	

group_manager_la_CPPFLAGS = 							\
	$(AM_CPPFLAGS)								\
	-I$(srcdir)/../								\
	-I$(top_srcdir)/src/nox/ 						\
	-D__COMPONENT_FACTORY_FUNCTION__=group_manager_get_factory
group_manager_la_SOURCES = group_manager.cc group_manager.hh
group_manager_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.json

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
