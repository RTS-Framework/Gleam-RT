IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32
  _Pointer_Stub@0 proc
ELSE
  Pointer_Stub proc
ENDIF

  db 0FAh, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h

IFDEF _WIN32
  _Pointer_Stub@0 endp
ELSE
  Pointer_Stub endp
ENDIF

end
