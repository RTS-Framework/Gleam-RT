IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32
  _Shield_Stub@0 proc
  INCLUDE <inst/shield_x86.inst>
  _Shield_Stub@0 endp
ELSE
  Shield_Stub proc
  INCLUDE <inst/shield_x64.inst>
  Shield_Stub endp
ENDIF

end
