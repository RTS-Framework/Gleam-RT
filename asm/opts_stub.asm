IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32
  _Option_Stub@0 proc
ELSE
  Option_Stub proc
ENDIF

INCLUDE <inst/option.inst>

IFDEF _WIN32
  _Option_Stub@0 endp
ELSE
  Option_Stub endp
ENDIF

end
