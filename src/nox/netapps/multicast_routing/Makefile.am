include ../../../Make.vars 

CONFIGURE_DEPENCIES = $(srcdir)/Makefile.am

EXTRA_DIST = \
	meta.json

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

pkglib_LTLIBRARIES =		\
	mc_routing_module.la	

mc_routing_module_la_CPPFLAGS = 							\
	$(AM_CPPFLAGS)								\
	-I$(srcdir)/../								\
	-I$(top_srcdir)/src/nox/ 						\
	-I$(top_srcdir)/src/nox/coreapps/ 					\
	-D__COMPONENT_FACTORY_FUNCTION__=mc_routing_module_get_factory
mc_routing_module_la_SOURCES = multicast_routing.cc multicast_routing.hh
mc_routing_module_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.json

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
