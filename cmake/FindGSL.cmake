find_path(GSL_INCLUDE_DIRS gsl/gsl)
mark_as_advanced(GSL_INCLUDE_DIRS)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GSL DEFAULT_MSG  GSL_INCLUDE_DIRS)
