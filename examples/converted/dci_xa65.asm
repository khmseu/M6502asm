Q .equ 128-1
.macro DCI A
Q .equ Q+1
DC(A)
.endmacro
RESLST: .byte 'E', 'N', 'D'|$80
.byte 'F', 'O', 'R'|$80
.byte 'N', 'E', 'X', 'T'|$80
