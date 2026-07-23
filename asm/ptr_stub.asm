IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32
  _Pointer_Stub@0 proc
ELSE
  Pointer_Stub proc
ENDIF

  ; magic mark and reserved data
  db 0FBh, 000h, 000h, 000h, 000h, 000h, 000h, 000h

  ; pointer slot
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h

IFDEF _WIN32
  _Pointer_Stub@0 endp
ELSE
  Pointer_Stub endp
ENDIF

end
